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

    redef record HTTP::Info += {
        cas_session: CAS::Info &optional;
        duo_session: CAS::Info &optional;
    };

    const cas_login_uri = /\/cas\/login/i &redef;
}

# Parse the Duo post body payload
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
    log$service = c$http$cas_session?$service ? c$http$cas_session$service : "<unknown>";
    log$lv_dist = c$http$cas_session$lv_dist;
    log$user_agent = c$http?$user_agent ? c$http$user_agent : "<unknown>";

    if(c$http?$status_code)
    {
        if(c$http$status_code == 401)
        {
            # CAS login failed
            log$cas_success = F;
            Log::write(CAS::LOG, log);
            return;
        }

        if(c$http?$set_cookie_vars && check_set_cookie(c$http$set_cookie_vars, "TGC") && c$http$status_code == 302) 
        {
            # CAS login successful
            log$cas_success = T;
            log$duo_enabled = F;
            Log::write(CAS::LOG, log);
            return;
        }

        if(c$http$status_code == 200) 
        {
            # CAS login successful
            log$cas_success = T;
            log$duo_enabled = T;
            Log::write(CAS::LOG, log);
            return;
        }
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
    log$service = c$http$duo_session?$service ? c$http$duo_session$service : "<unknown>";
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
        if(c$http$cas_session$username == "") {
            Reporter::warning(fmt("User ID was blank from %s. Incomplete CAS session.", c$id$orig_h));
            return;
        }

        # Grab the CAS service parameter
        # /cas/login?service=http://somesite.byu.edu
        service = find_all_urls(c$http$uri);
        for(uri in service)
        {
            c$http$cas_session$service = uri;
        }
        
        if(c$http$cas_session$password == "")
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
            if(c$http$duo_session$username == "") {
                Reporter::warning(fmt("User ID was blank from %s. Incomplete DUO session.", c$id$orig_h));
                return;
            }

            service = find_all_urls(c$http$uri);
            for(uri in service)
            {
                c$http$duo_session$service = uri;
            }

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
            session$username = lp_attrs["username"];
            c$http$duo_session = session;
        }

        if(/username/ in data)
        {
            lp_attrs = cas_parse_post_body(data);
            session$username = lp_attrs["username"];
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

event bro_init()
{
    # Create the new CAS event logging stream (cas.log)
    local stream = [$columns=Info, $path="cas"];
    Log::create_stream(CAS::LOG, stream);
}


