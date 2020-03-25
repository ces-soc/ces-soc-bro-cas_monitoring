
    ## Per user session state
    type SessionContext: record
    {
        user_agent: string &optional;  
        conn: string &optional;       
        id: conn_id &optional;
        cookie: set[string] &optional;    
        set_cookie: string_vec &optional;
        service: string &optional; 
        username: string &optional;
        password: string &optional;
        lv_dist: count &optional;
    };

    ## Time after which a seen cookie is forgotten.
    # const session_expiration = 90sec &redef;


    # global expire_doc: function(t: table[string] of table[string] of SessionContext, idx: string): interval;

    ## User state tracking table
    # global users: table[string] of table[string] of SessionContext &read_expire = session_expiration &expire_func = expire_doc &redef;

## This function expires documents in the user state tracking table when session_expiration has been reached.
## This is important for controlling memory consumption and making sure documents are cleaned out if Bro
## was unable to track the entire session
#function expire_doc(t: table[string] of table[string] of SessionContext, idx: string): interval
#{
#    if("cas" in t[idx] && "duo" !in t[idx] && /CASPRIVACY.*/ in t[idx]["cas"]$set_cookie)
#    {
#        # Build the record and write the log
#        local log: Info = [
#            $ts = network_time(),
#            $uid = t[idx]["cas"]$conn,
#            $id = t[idx]["cas"]$id
#        ];
#        log$username = t[idx]["cas"]$username;
#        log$service = t[idx]["cas"]$service;
#        log$pw_length = |t[idx]["cas"]$password|;
#        log$cas_success = T;
#        log$duo_enabled = T;
#        # log$duo_success = F; # Don't set since we don't know if the Duo challenge was successful or not
#        log$duo_timeout = T;
#        log$lv_dist = t[idx]["cas"]$lv_dist;
#        log$user_agent = t[idx]["cas"]?$user_agent ? t[idx]["cas"]$user_agent : "<unknown>";
#        Log::write(CAS::LOG, log);
#        # Redact password
#        t[idx]["cas"]$password = "<redacted>";
#        Reporter::warning(fmt("CAS EXPIRE: %s", t[idx]));
#    }
#    return 0 secs;
#}

#function check_logon_complete(c: connection, user_id: string)
#{
#    # Build the record and write the log
#    local log: Info = [
#        $ts = network_time(),
#        $uid = c$uid,
#        $id = c$id
#    ];
#
#    # TODO: Add condition if duo is detected but the initial CAS transaction was not detected
#    # In this case, we assume the CAS auth was successful if we detect the DUO auth worked
#    if(user_id != "")
#    {
#        if("cas" in users[user_id])
#        {
#            # Set common fields
#            log$username = users[user_id]["cas"]$username;
#            log$pw_length = |users[user_id]["cas"]$password|;
#            log$service = users[user_id]["cas"]?$service ? users[user_id]["cas"]$service : "<unknown>";
#            log$lv_dist = users[user_id]["cas"]$lv_dist;
#            log$user_agent = users[user_id]["cas"]?$user_agent ? users[user_id]["cas"]$user_agent : "<unknown>";
#
#            if("duo" !in users[user_id] && /CASTGC.*/ in users[user_id]["cas"]$set_cookie)
#            {
#                # Since we've detected the immediate setting of the CASTGT cookie, the CAS authentication was successful and
#                # there is no secondary MFA challenge
#                # CAS authentication was successful
#                # print("CAS authentication successful");
#                log$cas_success = T;
#                log$duo_enabled = F;
#            }
#            else if("duo" !in users[user_id] && /CASPRIVACY.*/ in users[user_id]["cas"]$set_cookie)
#            {
#                # When the CASPRIVACY cookie is set, the CAS auth was successful, but since a CASTGT cookie was not set, we assume
#                # the CAS login was successful and a seconday MFA auth is pending as we wait for CASTGT
#                # CAS authentication successful, MFA auth is pending
#                # This has been left here for future processing work if needed
#                # print("CAS authentication successful, MFA pending");
#                return;
#            }
#            else if("duo" in users[user_id] && (/CASTGC.*/ in users[user_id]["cas"]$set_cookie || /CASTGC.*/ in users[user_id]["duo"]$set_cookie))
#            {
#                # We see Duo session context has been set and we have detected the presence of the CASTGT cookie.
#                # CAS and DUO authentication was successful
#                # print("CAS and DUO authentication successful");
#                # Update the log record
#                log$cas_success = T;
#                log$duo_enabled = T;
#                log$duo_success = T;
#            }
#            else if("duo" !in users[user_id] && /(CASTGC.*|CASPRIVACY.*)/ !in users[user_id]["cas"]$set_cookie)
#            {
#                # CAS login failure was detected
#                # print("CAS login failure");
#                log$cas_success = F;
#            }
#            else
#            {
#                Reporter::warning(fmt("check_logon_complete for %s did not satisfy any condition", user_id));
#                return;
#            }
#
#            Log::write(CAS::LOG, log);
#            delete users[user_id];
#        }
#        else 
#        {
#            # Set common fields
#            log$username = users[user_id]["duo"]$username;
#            log$service = users[user_id]["duo"]?$service ? users[user_id]["duo"]$service : "<unknown>";
#            log$user_agent = users[user_id]["duo"]?$user_agent ? users[user_id]["duo"]$user_agent : "<unknown>";
#            if("duo" in users[user_id] && /CASTGC.*/ in users[user_id]["duo"]$set_cookie)
#            {
#                log$cas_success = T;
#                log$duo_enabled = T;
#                log$duo_success = T;
#                log$cas_assume = T;
#
#                Log::write(CAS::LOG, log);
#                delete users[user_id];
#            }
#            else
#            {
#                Reporter::warning(fmt("check_logon_complete for %s did not satisfy any condition", user_id));
#                return;
#            }
#
#        }
#
#    }
#}
