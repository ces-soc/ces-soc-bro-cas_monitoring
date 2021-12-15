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
        password: string &optional;
        ## CAS service (removed in favor of HTTP referrer)
        # service: string &log &optional;
        ## CAS service referrer
        referrer: string &log &optional;
        ## CAS authentication status
        cas_success: bool &log &optional;
        ## Duo success
        duo_success: bool &log &optional;
        ## Duo timeout
        duo_timeout: bool &log &optional;
        ## Duo detected
        duo_detected: bool &log &optional;
        ## CAS missing
        cas_assume: bool &log &optional;
        ## Levenshtein Distance
        lv_dist: count &log &optional;
        ## Password length
        pw_length: count &log &optional;
        ## User agent
        user_agent: string &log &optional;
    };

    redef record HTTP::Info += {
        cas_session: CAS::Info &optional;
        duo_session: CAS::Info &optional;
    };

    const cas_login_uri = /\/cas\/login/i &redef;
}

function duo_parse_post_body(post_body: string) : table[string] of string
{
    local params: string_vec;
    local attrs: table[string] of string;
    local username: string;
    attrs["username"] = "";

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
            if(1 in tmp) # Does the Duo response payload exist?
            {
                # Assign username and password values to attribute table
                # Below is an example of the Duo payload we process
                # Example: AUTH|<base64 string containing username>|<other base64 metadata>
                # Split the string on "|" (html encoded)
                local usertmp: string_vec = split_string(tmp[1], /\%7c/i);
                if(1 in usertmp) # Does the user exist?
                {
                    username = usertmp[1];
                    # Convert any encoded '=' on base64 string
                    if(/\%3d/i in username)
                    {
                        username = gsub(username, /\%3d/i, "=");
                    }
                    # Decoded example: nturley|DIVYTHFJ1XXXXXXXXX|1566430000
                    attrs["username"] = split_string(decode_base64(username), /\|/)[0];
                }
            }
        }
    }
    return attrs;
}

# Parse the CAS post body
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
        attrs[tmp[0]] = 1 in tmp ? unescape_URI(tmp[1]) : "";
    }

    return attrs;
}

function check_set_cookie(v: vector of string, val: string): bool
{
    for(idx in v)
    {
        if(v[idx] == val) { return T; }
    }
    return F;
}

# Function used to check the CAS login based on session information already collected
function check_cas_logon(c: connection)
{
    # Build the record and write the log
    local log: Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id
    ];

    # Set common fields
    # IMPORTANT: note that the password field is not being recorded in the log (make sure it stays that way)
    log$username = c$http$cas_session$username;
    log$pw_length = |c$http$cas_session$password|;
    # log$service = c$http$cas_session?$service ? c$http$cas_session$service : "<unknown>";
    log$referrer = c$http?$referrer ? c$http$referrer : "<unknown>";
    log$lv_dist = c$http$cas_session$lv_dist;
    log$user_agent = c$http?$user_agent ? c$http$user_agent : "<unknown>";
    log$duo_detected = c$http$cas_session?$duo_detected ? c$http$cas_session$duo_detected : F;

    if(c$http?$status_code)
    {
        if(c$http$status_code == 401)
        {
            # CAS login failed
            log$cas_success = F;
        }
        else if(c$http?$set_cookie_vars && check_set_cookie(c$http$set_cookie_vars, "TGC") && c$http$status_code == 302) 
        {
            # CAS login successful, no Duo
            log$cas_success = T;
        }
        else if(c$http$status_code == 200) 
        {
            log$cas_success = T; # Either direct CAS login without Duo, or Duo enabled, waiting for login. Check duo_detected field. 
        }
        else
        {
            log$cas_success = F; # Can't determine CAS login. Report warning. 
            Reporter::warning(fmt("Could not determine CAS login status from %s (%s) - HTTP CODE: %d.", c$id$orig_h, c$http$cas_session$username, c$http$status_code));
        }
        
        Log::write(CAS::LOG, log);
    }
}

function check_duo_logon(c: connection)
{
    # Build the record and write the log
    local log: Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id
    ];

    # Set common fields
    log$username = c$http$duo_session$username;
    # log$service = c$http$duo_session?$service ? c$http$duo_session$service : "<unknown>";
    log$referrer = c$http?$referrer ? c$http$referrer : "<unknown>";
    log$user_agent = c$http?$user_agent ? c$http$user_agent : "<unknown>";

    if(c$http?$status_code)
    {
        if(c$http$status_code == 401)
        {
            # CAS login failed
            log$duo_success = F;
            Log::write(CAS::LOG, log);
            return;
        }

        if(c$http?$set_cookie_vars && check_set_cookie(c$http$set_cookie_vars, "TGC") && c$http$status_code == 302) 
        {
            # CAS login successful
            log$duo_success = T;
            Log::write(CAS::LOG, log);
            return;
        }

        if(c$http$status_code == 200) 
        {
            # CAS login successful
            log$duo_success = T;
            Log::write(CAS::LOG, log);
            return;
        }
    }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    # Return if no URI is detected
    if(!c$http?$uri)
        return;

    # Return if we don't see a CAS URI signature
    if(cas_login_uri !in c$http$uri)
        return;

    if(is_orig == T)
        return;

    if(/signedDuoResponse/i in data && c$http?$cas_session)
    {
        c$http$cas_session$duo_detected = T;
    }
}

# Event for CAS login processing
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    # Return if no URI is detected
    if(!c$http?$uri)
        return;

    # Return if we don't see a CAS URI signature
    if(cas_login_uri !in c$http$uri)
        return;

    local service: set[string];

    if(c$http?$cas_session)
    {
        if(!c$http$cas_session?$username || c$http$cas_session$username == "") {
            Reporter::warning(fmt("User ID was blank from %s. Incomplete CAS session.", c$id$orig_h));
            return;
        }

        # Grab the CAS service parameter
        # /cas/login?service=http://somesite.byu.edu
        # service = find_all_urls(c$http$uri);
        # if(|service| != 0) # /cas/login?service=www.byu.edu
        # {
        #     for(uri in service)
        #     {
        #         c$http$cas_session$service = uri;
        #     }
        # }
        # else
        # {
        #     # Some CAS configurations do not include the service URI parameter. If this is the case, pull from HTTP referrer. 
        #     c$http$cas_session$service = c$http?$referrer ? c$http$referrer : "<unknown>";
        # }
        
        if(!c$http$cas_session?$password || c$http$cas_session$password == "")
        {
            # Return since login checks won't work if password is missing
            # TODO: Record cas log anyway for this event
            Reporter::warning(fmt("User ID %s had blank password. Incomplete CAS session.", c$http$cas_session$username));
            return;
        }

        # session$password = c$http$cas_password;
        c$http$cas_session$lv_dist = levenshtein_distance(c$http$cas_session$username, c$http$cas_session$password);

        check_cas_logon(c);

        # Since we know we're dealing with CAS payload at this point, redact the POST payload for data sensitivity
        c$http$post_body = "<redacted>";
    }
}

# Event for DUO login processing
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    # Return if no URI is detected
    if(!c$http?$uri)
        return;

    # Return if we don't see a CAS URI signature
    if(cas_login_uri !in c$http$uri)
        return;

    local service: set[string];

    if(c$http?$duo_session)
    {
        if(!c$http$duo_session?$username || c$http$duo_session$username == "") {
            Reporter::warning(fmt("User ID was blank from %s. Incomplete DUO session.", c$id$orig_h));
            return;
        }

        # service = find_all_urls(c$http$uri);
        # if(|service| != 0)
        # {
        #     for(uri in service)
        #     {
        #         c$http$duo_session$service = uri;
        #     }
        # }
        # else
        # {
        #     c$http$duo_session$service = c$http?$referrer ? c$http$referrer : "<unknown>";
        # }

        check_duo_logon(c);

        # Since we know we're dealing with CAS payload at this point, redact the POST payload for data sensitivity
        c$http$post_body = "<redacted>";
    }
}

event cas_post_bodies(f: fa_file, data: string)
{
    local lp_attrs: table[string] of string;
    local session: CAS::Info;
    for (cid in f$conns)
    {
        local c: connection = f$conns[cid];
        if(/signedDuoResponse=AUTH/ in data)
        {
            lp_attrs = duo_parse_post_body(data);
            if("username" !in lp_attrs || lp_attrs["username"] == "") {
                Reporter::warning(fmt("User ID was blank from %s. Incomplete DUO session.", c$id$orig_h));
                return;
            }
            session$username = lp_attrs["username"];

            c$http$duo_session = session;
        }

        if(/username/ in data)
        {
            lp_attrs = cas_parse_post_body(data);
            if("username" !in lp_attrs || lp_attrs["username"] == "") {
                Reporter::warning(fmt("User ID was blank from %s. Incomplete CAS session.", c$id$orig_h));
                return;
            }
            session$username = lp_attrs["username"]; 

            if("password" !in lp_attrs || lp_attrs["password"] == "") {
                Reporter::warning(fmt("User ID %s from %s was missing password in headers. Incomplete CAS session.", c$id$orig_h, session$username));
                return;
            }
            session$password = lp_attrs["password"];

            c$http$cas_session = session;
        }
    }
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=10
{
	if ( is_orig && c?$http && c$http?$method && c$http$method == "POST" 
        && c$http?$uri && cas_login_uri in c$http$uri)
	{
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=cas_post_bodies]);
	}
}

event zeek_init()
{
    # Create the new CAS event logging stream (cas.log)
    local stream = [$columns=Info, $path="cas"];
    Log::create_stream(CAS::LOG, stream);
}


