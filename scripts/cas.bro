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
    set_cookie: set[string] &optional;
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
    if("cas" in t[idx] && "duo" !in t[idx] && /CASPRIVACY=.*/ in join_string_set(t[idx]["cas"]$set_cookie, "-"))
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
        # log$password = "<redacted>";
        log$cas_success = T;
        log$duo_enabled = T;
        # log$duo_success = F; # Don't set since we don't know if the Duo challenge was successful or not
        log$duo_timeout = T;
        log$lv_dist = t[idx]["cas"]$lv_dist;
        if(t[idx]["cas"]?$user_agent)
        {
            log$user_agent = t[idx]["cas"]$user_agent;
        }
        Log::write(CAS::LOG, log);
        # Redact password
        t[idx]["cas"]$password = "<redacted>";
        Reporter::info(fmt("CAS EXPIRE: %s", t[idx]));
    }
    return 0 secs;
}

## User state tracking table
global users: table[string] of table[string] of SessionContext &read_expire = session_expiration &expire_func = expire_doc;

function cas_parse_post_body(post_body: string) : table[string] of string
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
        # Lowercase key values
        tmp[0] = to_lower(tmp[0]);
        tmp[1] = to_lower(tmp[1]);
        if(tmp[0] == "username" || tmp[0] == "password")
        {
            # Assign username and password values to attribute table
            attrs[tmp[0]] = unescape_URI(tmp[1]);
            # print fmt("idx = %d, element = %s", idx, params[idx]);
            # print fmt("ATTRS: %s", attrs);
        }
    }
    return attrs;
    
}

function duo_parse_post_body(post_body: string) : table[string] of string
{
    local params: string_vec;
    local attrs: table[string] of string;
    local username: string;
    # Reporter::info(fmt("DUO BODY: %s", post_body));

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

function get_cookie(hlist: mime_header_list): set[string]
{
    local cookies: set[string] = set();
    for ( h in hlist  )
    {
        if ( hlist[h]$name == "COOKIE" )
        {
            add cookies[hlist[h]$value];
        }
    }
    return cookies;
}

function get_set_cookie(hlist: mime_header_list): set[string]
{
    local cookies: set[string] = set();
    for ( h in hlist  )
    {
        if ( hlist[h]$name == "SET-COOKIE" )
        {
            add cookies[hlist[h]$value];
        }
    }
    return cookies;
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
        if("cas" in users[user_id] && "duo" !in users[user_id] && /CASTGC=TGT.*/ in join_string_set(users[user_id]["cas"]$set_cookie, "-"))
        {
            # Since we've detected the immediate setting of the CASTGT cookie, the CAS authentication was successful and
            # there is no secondary MFA challenge
            # CAS authentication was successful
            # print("CAS authentication successful");
            log$username = users[user_id]["cas"]$username;
            log$pw_length = |users[user_id]["cas"]$password|;
            log$service = users[user_id]["cas"]?$service ? users[user_id]["cas"]$service : "<unknown>";
            log$cas_success = T;
            log$duo_enabled = F;
            log$lv_dist = users[user_id]["cas"]$lv_dist;

            # Set the user agent
            if(users[user_id]["cas"]?$user_agent)
            {
                log$user_agent = users[user_id]["cas"]$user_agent;
            }

            Log::write(CAS::LOG, log);
            delete users[user_id];
        }
        else if("cas" in users[user_id] && "duo" !in users[user_id] && /CASPRIVACY=.*/ in join_string_set(users[user_id]["cas"]$set_cookie, "-"))
        {
            # When the CASPRIVACY cookie is set, the CAS auth was successful, but since a CASTGT cookie was not set, we assume
            # the CAS login was successful and a seconday MFA auth is pending as we wait for CASTGT

            # CAS authentication successful, MFA auth is pending
            # This has been left here for future processing work if needed
            # print("CAS authentication successful, MFA pending");
            return;
        }
        else if( "cas" in users[user_id] && 
            ("duo" in users[user_id] && !users[user_id]["duo"]?$set_cookie && "duo" in users[user_id] && users[user_id]["duo"]?$duo_trans) )
        {
            # print("CAS authentication successful, MFA detected and pending");
            return;

        }
        else if( "cas" in users[user_id] && 
            ("duo" in users[user_id] && users[user_id]["duo"]?$set_cookie && /CASTGC=TGT.*/ in join_string_set(users[user_id]["duo"]$set_cookie, "-")))
        {
            # At this point, we see Duo session context has been set and we have detected the presence of the CASTGT cookie.
            # CAS and DUO authentication was successful
            # print("CAS and DUO authentication successful");
            # print(users[user_id]);

            # Update the log record
            log$username = users[user_id]["cas"]$username;
            log$service = users[user_id]["cas"]?$service ? users[user_id]["cas"]$service : "<unknown>";
            log$pw_length = |users[user_id]["cas"]$password|;
            log$cas_success = T;
            log$duo_enabled = T;
            log$duo_success = T;
            log$lv_dist = users[user_id]["cas"]$lv_dist;

            # Set the user agent
            if(users[user_id]["cas"]?$user_agent)
            {
                log$user_agent = users[user_id]["cas"]$user_agent;
            }

            Log::write(CAS::LOG, log);
            delete users[user_id];
        }
        else if("cas" in users[user_id] && "duo" !in users[user_id] && /(CASTGC=TGT.*|CASPRIVACY=.*)/ !in join_string_set(users[user_id]["cas"]$set_cookie, "-"))
        {
            # CAS login failure was detected
            # print("CAS login failure");
            log$username = users[user_id]["cas"]$username;
            log$pw_length = |users[user_id]["cas"]$password|;
            log$service = users[user_id]["cas"]?$service ? users[user_id]["cas"]$service : "<unknown>";
            log$cas_success = F;
            log$lv_dist = users[user_id]["cas"]$lv_dist;

            # Set the user agent
            if(users[user_id]["cas"]?$user_agent)
            {
                log$user_agent = users[user_id]["cas"]$user_agent;
            }

            Log::write(CAS::LOG, log);
            delete users[user_id];
        }
        else
            return;
    }
}

# Duo transaction check
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    local str: string;
    local duo_attrs: string_vec;
    local duo_decode: string;
    local username: string;
    local user_id: string;
    local session: SessionContext;

    # Duo session initiation detected
    if( /sig_request.*TX\|.*APP\|/ in data )
    {
        # When the user CAS authenticates and hits the DUO challenge screen, we look for the sig_request
        # attribute, which flags that the user is Duo enabled
        # 'sig_request': 
        # 'TX|XXXXcmxleXxESTA1UzBIM1kzQUQzSlRUWUNDVHwxNTQ2OTI2XXX
        # |XXXX1ec755ea3db07ca0398a639bd1e3da4bXXXX:APP
        # |XXXXcmxleXxESTA1UzBIM1kzQUQzSlRUWUNDVHwxNTQ2OTI5XXXX|9068a02eb2b03bb9d67b1850a9156d667cabXXXX',
        str = find_last(data, /sig_request.*TX\|.*APP\|/);

        # Tokenize the above sig_request attributes
        duo_attrs = split_string(str, /\|/);
        # print(duo_attrs);

        # Decode the base64 username token
        # This produces a string like 'username|DI05S0H3Y3AD3JXXXXXX|154595XXXX'
        duo_decode = decode_base64(duo_attrs[1]);

        # Now grab the username from the above decoded string
        username = split_string(duo_decode, /\|/)[0];
        user_id = fmt("%s-%s", c$id$orig_h, username);
        session$conn = c$uid;
        session$id = c$id;
        session$username = username;

        # Store the attributes if we want them for further processing
        session$duo_trans = duo_attrs;

        # Don't need to set user_agent since it should be set in the CAS session
        # session$user_agent = c$http?$user_agent ? c$http$user_agent : "";
        if (user_id != "")
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
                    Reporter::warning(fmt("UserID %s is missing CAS data in state tracking table. We never saw CAS initiation.", user_id));
                    # TODO: Expand this to assume CAS auth was successful since we see a Duo challenge
                }
            }
            else
            {
                Reporter::warning(fmt("UserID %s not in state tracking table when processing Duo event. We never saw CAS initiation.", user_id));
                # TODO: Expand this to assume CAS auth was successful since we see a Duo challenge
            }
        }
        else
        {
            Reporter::warning("User ID was blank in processing http_entity_data for Duo");
        }
    }
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=10
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
 
    if(c$http?$post_body)
    {
        # CAS initial POST transaction setup
        if(/username/ in c$http$post_body)
        {
            # Since we see username, this is a new post
            lp_attrs = cas_parse_post_body(c$http$post_body);
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
                Reporter::warning(fmt("User ID %s was missing password in headers. Incomplete CAS session.", session$username));
                return;
            }

            session$password = lp_attrs["password"];
            session$lv_dist = levenshtein_distance(lp_attrs["username"], lp_attrs["password"]);

            session$set_cookie = get_set_cookie(hlist);
            if(c$http?$user_agent)
            {
                # Set user agent if available
                session$user_agent = c$http$user_agent;
            }
            users[user_id] = table(
                ["cas"] = session
            );
            check_logon_complete(c, user_id);

            # Since we know we're dealing with CAS payload at this point, redact the POST payload for data sensitivity
            c$http$post_body = "<redacted>";
        }
    }
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=-10
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

    if(c$http?$post_body) {
        if(/signedDuoResponse/ in c$http$post_body)
        {
            lp_attrs = duo_parse_post_body(c$http$post_body);
            user_id = fmt("%s-%s", c$id$orig_h, lp_attrs["username"]);
            session$conn = c$uid;
            session$id = c$id;
            session$username = lp_attrs["username"];
            session$set_cookie = get_set_cookie(hlist);
            if(user_id != "") {
                if(user_id in users) {
                    if("cas" in users[user_id]) {
                        users[user_id] = table(
                            ["cas"] = users[user_id]["cas"],
                            ["duo"] = session
                        );
                        check_logon_complete(c, user_id);
                    }
                    else
                    {
                        Reporter::warning(fmt("UserID %s is missing CAS data in state tracking table when handling Duo. We never saw CAS initiation.", user_id));
                        # TODO: Expand this to assume CAS auth was successful since we see a Duo challenge
                    }
                }
                else
                {
                    Reporter::warning(fmt("UserID %s not in state tracking table when processing Duo event. We never saw CAS initiation.", user_id));
                    # TODO: Expand this to assume CAS auth was successful since we see a Duo challenge
                }
            }
            else
            {
                Reporter::warning("User ID was blank in processing http_all_headers for Duo");
            }
            # print(join_string_set(users[user_id]["duo"]$set_cookie, "-"));
        }

    }
}

