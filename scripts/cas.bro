##! Brigham Young University
##! Module for handling SSL inspected CAS events

@load base/protocols/http
@load base/utils/urls

module CAS;

export {
    ## CAS event log ID definition.
    redef enum Log::ID += { LOG };

    type Info: record {
        ## CAS event timestamp
        ts:   time    &log;
        ## Unique ID for the connection.
        uid:  string  &log;
        ## Connection details.
        id:   conn_id &log;
        ## CAS username detected
        username:  string  &log &optional;
        ## CAS password detected
        password: string  &log &optional;
        ## CAS service
        service: string &log &optional;
        ## CAS authentication status
        cas_success: bool &log &optional;
        ## Duo auth
        duo_enabled: bool &log &optional;
        ## Duo success
        duo_success: bool &log &optional;
        ## Duo timeout
        duo_timeout: bool &log &optional;
        ## CAS missing
        cas_assume: bool &log &optional;
        ## Levenshtein Distance
        lv_dist: count &log &optional;
        ## Password length
        pw_length: count &log &optional;
        ## User agent
        user_agent: string &log &optional;
    };

    ## Bool to determine whether passwords are redacted in the log or not
    const redact_password: bool = T &redef;

    const cas_login_uri = /\/[cA][aA][sS]\/[lL][oO][gG][iI][nN]\?/ &redef;
    # username=<username>&password=<password>&execution=e1s1&lt=LT-xxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&_eventId=submit
    const cas_user_pass = /[uU][sS][eE][rR][nN][aA][mM][eE]=\S+\&][pP][aA][sS][sS][wW][oO][rR][dD]=\S+\&/ &redef;

    ## IP entrypoints for campus CS services
    const cas_infra: set[addr] = {
    } &redef;

    ## Time after which a seen cookie is forgotten.
    const session_expiration = 90sec &redef;

}

## Per user session state
type SessionContext: record
{
    user_agent: string &optional;  
    conn: string &optional;       
    id: conn_id &optional;
    cookie: set[string] &optional;    
    set_cookie: string &optional;
    duo_trans: string_vec &optional;
    service: string &optional; 
    username: string &optional;
    password: string &optional;
    lv_dist: count &optional;
};


# Map cookies to their contextual state.
#global users: table[string] of SessionContext &read_expire = session_expiration;

event bro_init()
{
    # Create the new CAS event logging stream (cas.log)
    local stream = [$columns=Info, $path="cas"];
    Log::create_stream(CAS::LOG, stream);
}

## This function expires documents in the user state tracking table when session_expiration has been reached.
## This is important for controlling memory consumption and making sure documents are cleaned out if Bro
## was unable to track the entire session
function expire_doc(t: table[string] of table[string] of SessionContext, idx: string): interval
{
    if("cas" in t[idx] && "duo" !in t[idx] && /CASPRIVACY.*/ in t[idx]["cas"]$set_cookie)
    {
        # Build the record and write the log
        local log: Info = [
            $ts = network_time(),
            $uid = t[idx]["cas"]$conn,
            $id = t[idx]["cas"]$id
        ];
        log$username = t[idx]["cas"]$username;
        log$service = t[idx]["cas"]$service;
        log$pw_length = |t[idx]["cas"]$password|;
        log$cas_success = T;
        log$duo_enabled = T;
        # log$duo_success = F; # Don't set since we don't know if the Duo challenge was successful or not
        log$duo_timeout = T;
        log$lv_dist = t[idx]["cas"]$lv_dist;
        log$user_agent = t[idx]["cas"]?$user_agent ? t[idx]["cas"]$user_agent : "<unknown>";
        Log::write(CAS::LOG, log);
        # Redact password
        t[idx]["cas"]$password = "<redacted>";
        Reporter::warning(fmt("CAS EXPIRE: %s", t[idx]));
    }
    return 0 secs;
}

## User state tracking table
global users: table[string] of table[string] of SessionContext &read_expire = session_expiration &expire_func = expire_doc;

function duo_parse_post_body(post_body: string) : table[string] of string
{
    local params: string_vec;
    local attrs: table[string] of string;
    local username: string;

    # First, split the general POST parameters
    params = split_string(post_body, /\&/);

    # Second, build table of key/value pairs
    for(idx in params)
    {
        # Split the key/value pairs
        local tmp: string_vec = split_string(params[idx], /=/);
        # Grab the Duo response payload
        if(tmp[0] == "signedDuoResponse")
        {
            # Assign username and password values to attribute table
            # Split the string on "|" (html encoded)
            username = split_string(tmp[1], /\%7[cC]/)[1];
            # Convert any encoded '=' on base64 string
            if(/\%3[dD]/ in username)
            {
                username = gsub(username, /\%3[dD]/, "=");
            }
            attrs["username"] = split_string(decode_base64(username), /\|/)[0];
        }
    }
    return attrs;
}

function parse_post_body(post_body: string) : table[string] of string
{
    local params: string_vec;
    local attrs: table[string] of string;

    # First, split the POST parameters
    params = split_string(post_body, /\&/);

    # Second, build table of key/value pairs
    for(idx in params)
    {
        # Split the key/value pairs
        local tmp: string_vec = split_string(params[idx], /=/);
        attrs[tmp[0]] = 1 in tmp ? unescape_URI(tmp[1]) : "";
    }

    return attrs;
}

function check_logon_complete(c: connection, user_id: string)
{
    # Build the record and write the log
    local log: Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id
    ];

    # TODO: Add condition if duo is detected but the initial CAS transaction was not detected
    # In this case, we assume the CAS auth was successful if we detect the DUO auth worked
    if(user_id != "")
    {
        if("cas" in users[user_id])
        {
            # Set common fields
            log$username = users[user_id]["cas"]$username;
            log$pw_length = |users[user_id]["cas"]$password|;
            log$service = users[user_id]["cas"]?$service ? users[user_id]["cas"]$service : "<unknown>";
            log$lv_dist = users[user_id]["cas"]$lv_dist;
            log$user_agent = users[user_id]["cas"]?$user_agent ? users[user_id]["cas"]$user_agent : "<unknown>";

            if("duo" !in users[user_id] && /CASTGC.*/ in users[user_id]["cas"]$set_cookie)
            {
                # Since we've detected the immediate setting of the CASTGT cookie, the CAS authentication was successful and
                # there is no secondary MFA challenge
                # CAS authentication was successful
                # print("CAS authentication successful");
                log$cas_success = T;
                log$duo_enabled = F;
            }
            else if("duo" !in users[user_id] && /CASPRIVACY.*/ in users[user_id]["cas"]$set_cookie)
            {
                # When the CASPRIVACY cookie is set, the CAS auth was successful, but since a CASTGT cookie was not set, we assume
                # the CAS login was successful and a seconday MFA auth is pending as we wait for CASTGT
                # CAS authentication successful, MFA auth is pending
                # This has been left here for future processing work if needed
                # print("CAS authentication successful, MFA pending");
                return;
            }
            else if("duo" in users[user_id] && (/CASTGC.*/ in users[user_id]["cas"]$set_cookie || /CASTGC.*/ in users[user_id]["duo"]$set_cookie))
            {
                # We see Duo session context has been set and we have detected the presence of the CASTGT cookie.
                # CAS and DUO authentication was successful
                # print("CAS and DUO authentication successful");
                # Update the log record
                log$cas_success = T;
                log$duo_enabled = T;
                log$duo_success = T;
            }
            else if("duo" !in users[user_id] && /(CASTGC.*|CASPRIVACY.*)/ !in users[user_id]["cas"]$set_cookie)
            {
                # CAS login failure was detected
                # print("CAS login failure");
                log$cas_success = F;
            }
            else
            {
                Reporter::warning(fmt("check_logon_complete for %s did not satisfy any condition", user_id));
                return;
            }

            Log::write(CAS::LOG, log);
            delete users[user_id];
        }
        else 
        {
            # Set common fields
            log$username = users[user_id]["duo"]$username;
            log$service = users[user_id]["duo"]?$service ? users[user_id]["duo"]$service : "<unknown>";
            log$user_agent = users[user_id]["duo"]?$user_agent ? users[user_id]["duo"]$user_agent : "<unknown>";
            if("duo" in users[user_id] && /CASTGC.*/ in users[user_id]["duo"]$set_cookie)
            {
                log$cas_success = T;
                log$duo_enabled = T;
                log$duo_success = T;
                log$cas_assume = T;

                Log::write(CAS::LOG, log);
                delete users[user_id];
            }
            else
            {
                Reporter::warning(fmt("check_logon_complete for %s did not satisfy any condition", user_id));
                return;
            }

        }

    }
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=10
{
    # Return if no URI is detected
    if(!c$http?$uri)
        return;

    # Return if we don't see a CAS URI signature
    if(cas_login_uri !in c$http$uri)
        return;

    # print(hlist);
    local lp_attrs: table[string] of string;
    local session: SessionContext;
    local user_id: string;

    if(c$http?$post_body && !is_orig)
    {
        # CAS initial POST transaction setup
        if(/username/ in c$http$post_body)
        {
            # Since we see username, this is a new post
            lp_attrs = parse_post_body(c$http$post_body);
            if("username" !in lp_attrs || lp_attrs["username"] == "") {
                Reporter::warning(fmt("User ID was missing in headers from %s. Incomplete CAS session.", c$id$orig_h));
                return;
            }
            user_id = fmt("%s-%s", c$id$orig_h, lp_attrs["username"]);
            # print fmt("USER: %s", user_id);
            
            # Grab the CAS service parameter
            # /cas/login?service=http://somesite.byu.edu
            local service: set[string] = find_all_urls(c$http$uri);
            for(uri in service)
            {
                session$service = uri;
            }
            
            session$conn = c$uid;
            session$id = c$id;
            session$username = lp_attrs["username"];

            if("password" !in lp_attrs)
            {
                # Return since login checks won't work if password is missing
                # TODO: Record cas log anyway for this event
                Reporter::warning(fmt("User ID %s was missing password in headers. Incomplete CAS session.", session$username));
                return;
            }

            session$password = lp_attrs["password"];
            session$lv_dist = levenshtein_distance(lp_attrs["username"], lp_attrs["password"]);

            if(c$http?$set_cookie_vars)
            {
                session$set_cookie = join_string_vec(c$http$set_cookie_vars, "-");
            }
            else
            {
                session$set_cookie = "";
            }

            # Set user agent if available
            session$user_agent = c$http?$user_agent ? c$http$user_agent : "<unknown>";

            users[user_id] = table(
                ["cas"] = session
            );
            check_logon_complete(c, user_id);

            # Since we know we're dealing with CAS payload at this point, redact the POST payload for data sensitivity
            c$http$post_body = "<redacted>";
        }
    }
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-10
{
    # Return if no URI is detected
    if(!c$http?$uri)
        return;

    # Return if we don't see a CAS URI signature
    if(cas_login_uri !in c$http$uri)
        return;

    # print(hlist);
    local lp_attrs: table[string] of string;
    local session: SessionContext;
    local user_id: string;

    if(c$http?$post_body && !is_orig) 
    {
        if(/signedDuoResponse/ in c$http$post_body)
        {
            lp_attrs = duo_parse_post_body(c$http$post_body);
            user_id = fmt("%s-%s", c$id$orig_h, lp_attrs["username"]);
            session$conn = c$uid;
            session$id = c$id;
            session$username = lp_attrs["username"];
            if(c$http?$set_cookie_vars)
            {
                session$set_cookie = join_string_vec(c$http$set_cookie_vars, "-");
            }
            else
            {
                session$set_cookie = "";
            }
            # Set user agent if available
            session$user_agent = c$http?$user_agent ? c$http$user_agent : "<unknown>";
            local service: set[string] = find_all_urls(c$http$uri);
            for(uri in service)
            {
                session$service = uri;
            }

            if(user_id != "") 
            {
                if(user_id in users) 
                {
                    if("cas" in users[user_id]) 
                    {
                        users[user_id] = table(
                            ["cas"] = users[user_id]["cas"],
                            ["duo"] = session
                        );
                        check_logon_complete(c, user_id);
                    }
                    else
                    {
                        Reporter::warning(fmt("UserID %s (%s) is missing CAS data in state table when handling Duo. We never saw CAS initiation.", user_id, c$uid));
                        # TODO: Expand this to assume CAS auth was successful since we see a Duo challenge
                    }
                }
                else
                {
                    Reporter::warning(fmt("UserID %s (%s) not in state table when handling Duo event. CAS initiation missing. Assume CAS success.", user_id, c$uid));
                    users[user_id] = table(
                        ["duo"] = session
                    );
                    check_logon_complete(c, user_id);
                }
            }
            else
            {
                Reporter::warning("User ID was blank in processing http_message_done event for Duo");
            }
        }

    }
}

#event bro_done()
#{
#    print("bro_done()");
#    print(users);
#}
