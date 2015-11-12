module Haproxy =
    autoload xfm

    let comment = [ label "#comment" . del /[ \t]*#[ \t]*/ "# "
        . store /([^ \t\r\n].*[^ \t\r\n]|[^ \t\r\n])/ ? ]

    let eol = comment ? . Util.eol
    let hard_eol = del "\n" "\n"
    let indent = del /[ \t]+/ "    "
    let optional_indent = ( del /[ \t]*/ "" ) ?
    let ws = del /[ \t]+/ " "
    let empty = eol
    let store_to_eol = store /[^ \r\t\n][^#\n\r]*[^ \r\t\n#]|[^ \t\n\r]/
    let word = /[^# \n\t]+/
    let store_to_ws = ws? . store word
    let store_time = ws? . store /[0-9]+(us|ms|s|m|h|d)?/

    let simple_option (r:regexp) = [ indent . key r ] . eol
    let kv_option (r:regexp) = [ indent . key r . ws . store_to_eol ] . eol
    let kv_or_simple (r:regexp) = ( kv_option r | simple_option r )
    let true_bool_option (r:regexp) = [ Util.del_str "option" . ws . key r . value "true" ] . eol
    let false_bool_option (r:regexp) = [ Util.del_str "no" . ws . Util.del_str "option" . ws . key r . value "false" ] . eol
    let bool_option (r:regexp) = indent . ( false_bool_option r | true_bool_option r )

    (*************************************************************************
      LOG OPTION
     *************************************************************************)
    let log_facility = "kern" | "user" | "mail" | "daemon" | "auth" | "syslog"
                     | "lpr" | "news" | "uucp" | "cron" | "auth2" | "ftp"
                     | "ntp" | "audit" | "alert" | "cron2" | "local0"
                     | "local1" | "local2" | "local3" | "local4" | "local5"
                     | "local6" | "local7"
    let log_level = "emerg" | "alert" | "crit" | "err" | "warning" | "notice"
                  | "info" | "debug"

    let log_opt = [ indent . key "log" .
        ws . [ label "address" . store_to_ws ] .
        ( ws . [Util.del_str "len" . ws . label "length" . store_to_ws] ) ? .
        ws . [ label "facility" . store log_facility ] .
        (
            ws . [ label "level" . store log_level ] .
            ( ws . [ label "minlevel" . store log_level ] )?
        )? ] . eol

    (*************************************************************************
      STATS OPTION
     *************************************************************************)
    let stats_level = "user" | "operator" | "admin"
    let stats_uid = [ key /(uid|user)/ . ws . store_to_ws ]
    let stats_gid = [ key /(gid|group)/ . ws . store_to_ws ]
    let stats_mode = [ key "mode" . ws . store_to_ws ]
    let stats_socket = [ indent . Util.del_str "stats" . ws . Util.del_str "socket" .
        label "stats_socket" . [ ws . label "path" . store_to_ws ] .
        ( [ ws . key /(uid|user)/ . ws . store_to_ws ] )? .
        ( [ ws . key /(gid|group)/ . ws . store_to_ws ] )? .
        ( [ ws . key "mode" . ws . store_to_ws ] )? .
        ( [ ws . key "level" . ws . store stats_level ] )?
        ] . eol
    let stats_timeout = [ indent . Util.del_str "stats" . ws . Util.del_str "timeout" .
        label "stats_timeout" . ws . store_time ] . eol
    let stats_maxconn =  [ indent . Util.del_str "stats" . ws . Util.del_str "maxconn" .
        label "stats_maxconn" . ws . store /[0-9]+/ ] . eol
    let stats = ( stats_socket | stats_timeout | stats_maxconn )


    (*************************************************************************
      USER LISTS
     *************************************************************************)
    let userlist_group =
        let name = [ label "name" . store Rx.no_spaces ] in
        let group_user = [ label "user" . store /[^ \t\n,#]+/ ] in
        let users = [ key "users" . Sep.space . group_user .
            ( Util.del_str "," . group_user )* ] in
        indent . [ key "group" . Sep.space . name . ( Sep.space . users)? ] . eol

    let userlist_user =
        let name = [ label "name" . store Rx.no_spaces ] in
        let password = [ key /password|insecure-password/ . Sep.space .
            store Rx.no_spaces ] in
        let user_group = [ label "group" . store /[^ \t\n,#]+/ ] in
        let groups = [ key "groups" . Sep.space . user_group .
            ( Util.del_str "," . user_group )* ] in
        indent . [ key "user" . Sep.space . name .
            ( Sep.space . password )? . ( Sep.space . groups )? ] . eol

    let userlist =
        let name = [ label "name" . store Rx.no_spaces ] in
        [ key "userlist" . Sep.space . name . eol .
            ( userlist_user | userlist_group | empty )* ]

    (*************************************************************************
     SERVER AND DEFAULT-SERVER
     *************************************************************************)
    let source =
        let addr = [ label "address" . store (/[^ \t\n:#]+/ - /client(ip)?|hdr_ip.*/) ]
        in let port = [ label "port" . store Rx.no_spaces ]
        in let addr_and_port = addr . ( Util.del_str ":" . port )?
        in let client = [ key "client" ]
        in let clientip = [ key "clientip" ]
        in let interface = [ key "interface" . Sep.space . store Rx.no_spaces ]
        in let hdr = [ label "header" . store /[^ \t\n,\)#]+/ ]
        in let occ = [ label "occurrence" . store /[^ \t\n\)#]+/ ]
        in let hdr_ip = Util.del_str "hdr_ip(" . hdr .
            ( Util.del_str "," . occ )? . Util.del_str ")"
        in let usesrc = [ key "usesrc" . Sep.space . ( clientip | client | addr_and_port | hdr_ip ) ]
        in [ key "source" . Sep.space . addr_and_port .
            ( Sep.space . ( usesrc | interface ) )? ]

    let server_options =
        let health_addr = [ key "health_address" . Sep.space . store Rx.no_spaces ] in
        let backup = [ key "backup" ] in
        let check = [ key "check" ] in
        let cookie = [ key "cookie" . Sep.space . store Rx.no_spaces ] in
        let disabled = [ key "disabled" ] in
        let id = [ key "id" . Sep.space . store Rx.no_spaces ] in
        let observe = [ key "observe" . Sep.space . store Rx.no_spaces ] in
        let redir = [ key "redir" . Sep.space . store Rx.no_spaces ] in
        let server_source = source in
        let track = [ key "track" . Sep.space .
            ( [ label "proxy" . store /[^ \t\n\/#]+/ . Util.del_str "/" ] )? .
            [ label "server" . store /[^ \t\n\/#]+/ ] ] in
        ( health_addr | backup | check | cookie | disabled | id | observe |
            redir | server_source | track )

    let default_server_options =
        let error_limit = [ key "error-limit" . Sep.space . store Rx.no_spaces ] in
        let fall = [ key "fall" . Sep.space . store Rx.no_spaces ] in
        let inter = [ key "inter" . Sep.space . store Rx.no_spaces ] in
        let fastinter = [ key "fastinter" . Sep.space . store Rx.no_spaces ] in
        let downinter = [ key "downinter" . Sep.space . store Rx.no_spaces ] in
        let maxconn = [ key "maxconn" . Sep.space . store Rx.no_spaces ] in
        let maxqueue = [ key "maxqueue" . Sep.space . store Rx.no_spaces ] in
        let minconn = [ key "minconn" . Sep.space . store Rx.no_spaces ] in
        let on_error = [ key "on-error" . Sep.space . store Rx.no_spaces ] in
        let health_port = [ key "health_port" . Sep.space . store Rx.no_spaces ] in
        let rise = [ key "rise" . Sep.space . store Rx.no_spaces ] in
        let slowstart = [ key "slowstart" . Sep.space . store Rx.no_spaces ] in
        let weight = [ key "weight" . Sep.space . store Rx.no_spaces ] in
        ( error_limit | fall | inter | fastinter | downinter | maxconn |
            maxqueue | minconn | on_error | health_port | rise | slowstart |
            weight )

    let default_server = indent . [ key "default-server" .
        ( Sep.space . default_server_options )+ ] . eol

    let server =
        let name = [ label "name" . store Rx.no_spaces ] in
        let addr = [ label "address" . store /[^ \t\n:#]+/ ] in
        let port = [ label "port" . store Rx.no_spaces ] in
        let addr_and_port = addr . ( Util.del_str ":" . port )? in
        let options = ( server_options | default_server_options ) in
        indent . [ key "server" . Sep.space . name . Sep.space .
            addr_and_port . ( Sep.space . options )* ] . eol

    (*************************************************************************
      PROXY OPTIONS
     *************************************************************************)
    let acl = indent . [ key "acl" . ws
        . [ label "name" . store_to_ws ] . ws
        . [ label "value" . store_to_eol ]
        ] . eol

    let appsession = indent . [ key "appsession" . ws
        . [ label "cookie" . store_to_ws ] . ws
        . [ key "len" . store_to_ws ] . ws
        . [ key "timeout" . store_time ]
        . ( ws . [ key "request-learn" ] )?
        . ( ws . [ key "prefix" ] )?
        . ( ws . [ key "mode" . store /(path-parameters|query-string)/ ] )?
        ] . eol

    let backlog = kv_option "backlog"

    let balance = indent . [ key "balance" . ws
        . [ label "algorithm" . store_to_ws ]
        . ( ws . [ label "params" . store_to_eol ] )?
        ] . eol


    let bind_address = [ label "bind_addr" . ( [ label "address" . store /[^ \t,]+/ ] )?
        . Util.del_str ":" . [ label "port" . store /[0-9-]+/ ] ]
    let bind_address_list = bind_address . ( Util.del_str "," . bind_address)*
    let bind = indent . [ key "bind" . ws
        . bind_address_list
        . ( ws . [ key "interface" . store_to_ws ] )?
        . ( ws . [ key "mss" . store_to_ws ] )?
        . ( ws . [ key "transparent" ] )?
        . ( ws . [ key "id" . store_to_ws ] )?
        . ( ws . [ key "name" . store_to_ws ] )?
        . ( ws . [ key "defer-accept" ] )?
        ] . eol

    let bind_process_id = [ key /[0-9]+/ ]
    let bind_process_id_list = [ label "number"
        . bind_process_id . ( ws . bind_process_id )*
        ]
    let bind_process = indent . [ key "bind-process" . ws
        . (store /(all|odd|even)/|bind_process_id_list)
        ] . eol

    let block = indent . [ key "block" . ws
        . [ label "condition" . store_to_eol ]
        ] . hard_eol

    let capture_cookie = indent . Util.del_str "capture" . ws . Util.del_str "cookie" . ws
        . [ label "capture_cookie"
            . [ label "name" . store_to_ws ] . ws
            . [ label "len" . store /[0-9]+/ ]
        ] . eol

    let capture_request_header = indent
        . Util.del_str "capture request header" . ws
        . [ label "capture_request_header"
            . [ label "name" . store_to_ws ] . ws
            . [ key "len" . ws . store /[0-9]+/ ]
        ] . eol

    let capture_response_header = indent
        . Util.del_str "capture response header" . ws
        . [ label "capture_response_header"
            . [ label "name" . store_to_ws ] . ws
            . [ label "len" . store /[0-9]+/ ]
        ] . eol

    let clitimeout = kv_option "clitimeout"

    let contimeout = kv_option "contimeout"

    let cookie = indent . [ key "cookie" . ws
        . [ label "name" . store_to_ws ]
        . ( ws . [ label "method" . store /(rewrite|insert|prefix)/ ] )?
        . ( ws . [ key "indirect" ] )?
        . ( ws . [ key "nocache" ] )?
        . ( ws . [ key "postonly" ] )?
        . ( ws . [ key "preserve" ] )?
        . ( ws . [ key "httponly" ] )?
        . ( ws . [ key "secure" ] )?
        . ( ws . [ key "domain" . store_to_ws ] )?
        . ( ws . [ key "maxidle" . store_time ] )?
        . ( ws . [ key "maxlife" . store_time ] )?
        ] . eol

    (* #XXX default-server *)

    let default_backend = kv_option "default_backend"

    let disabled = simple_option "disabled"

    let dispatch = indent . [ key "dispatch" . ws
        . [ label "address" . store /[^ \t,]+/ ]
        . Util.del_str ":" . [ label "port" . store /[0-9-]+/ ] ]

    let enabled = simple_option "enabled"

    let errorfile = indent . [ key "errorfile" . ws
        . [ label "code" . store /[0-9]+/ ] . ws
        . [ label "file" . store_to_eol ]
        ] . eol

    let error_redir (keyword:string) = indent . [ key keyword . ws
        . [ label "code" . store /[0-9]+/ ] . ws
        . [ label "url" . store_to_eol ]
        ] . eol

    let errorloc = error_redir "errorloc"
    let errorloc302 = error_redir "errorloc302"
    let errorloc303 = error_redir "errorloc303"

    let force_persist = indent . [ key "force-persist" . ws
        . [ label "condition" . store_to_eol ]
        ] . eol

    let fullconn = kv_option "fullconn"

    let grace = kv_option "grace"

    let hash_type = kv_option "hash-type"

    let http_check_disable_on_404 = indent
        . Util.del_str "http-check" . ws . Util.del_str "disable-on-404"
        . [ label "http_check_disable_on_404" ] . eol

    let http_check_expect = indent . Util.del_str "http-check" . ws . Util.del_str "expect"
        . [ label "http_check_expect"
            . ( ws . [ Util.del_str "!" . label "not" ] )?
            . ws . [ label "match" . store /(status|rstatus|string|rstring)/ ]
            . ws . [ label "pattern" . store_to_eol ]
        ] . eol

    let http_check_send_state = indent . Util.del_str "http-check" . ws . Util.del_str "send-state"
        . [ label "http_check_keep_state" ] . eol

    let http_request =
        let allow = [ key "allow" ]
        in let deny = [ key "deny" ]
        in let realm = [ key "realm" . Sep.space . store Rx.no_spaces ]
        in let auth = [ key "auth" . ( Sep.space . realm )? ]
        in let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in indent . [ Util.del_str "http-request" . label "http_request" .
            Sep.space . ( allow | deny | auth ) . ( Sep.space . cond )? ]
            . eol

    let http_send_name_header = kv_or_simple "http-send-name-header"

    let id = kv_option "id"

    let ignore_persist = indent . [ key "ignore-persist" . ws
        . [ label "condition" . store_to_eol ]
        ] . eol

    let log = (indent . [ key "log" . ws . store "global" ] . eol ) | log_opt |
        (indent . Util.del_str "no" . ws . [ key "log" . value "false" ] . eol)

    let maxconn = kv_option "maxconn"

    let mode = kv_option "mode"

    let monitor_fail = indent . Util.del_str "monitor" . ws . Util.del_str "fail"
        . [ key "monitor_fail" . ws
            . [ label "condition" . store_to_eol ]
        ] . eol

    let monitor_net = kv_option "monitor-net"

    let monitor_uri = kv_option "monitor-uri"

    let abortonclose = bool_option "abortonclose"

    let accept_invalid_http_request = bool_option "accept-invalid-http-request"

    let accept_invalid_http_response = bool_option "accept-invalid-http-response"

    let allbackups = bool_option "allbackups"

    let checkcache = bool_option "checkcache"

    let clitcpka = bool_option "clitcpka"

    let contstats = bool_option "contstats"

    let dontlog_normal = bool_option "dontlog-normal"

    let dontlognull = bool_option "dontlognull"

    let forceclose = bool_option "forceclose"

    let forwardfor =
        let except = [ key "except" . Sep.space . store Rx.no_spaces ]
        in let header = [ key "header" . Sep.space . store Rx.no_spaces ]
        in let if_none = [ key "if-none" ]
        in indent . [ Util.del_str "option" . ws . Util.del_str "forwardfor" . label "forwardfor" .
            ( Sep.space . except )? . ( Sep.space . header )? .
            ( Sep.space . if_none )? ] . eol

    let http_no_delay = bool_option "http-no-delay"

    let http_pretend_keepalive = bool_option "http-pretend-keepalive"

    let http_server_close = bool_option "http-server-close"

    let http_use_proxy_header = bool_option "http-use-proxy-header"

    let httpchk =
        let uri = [ label "uri" . Sep.space . store Rx.no_spaces ]
        in let method = [ label "method" . Sep.space . store Rx.no_spaces ]
        in let version = [ label "version" . Sep.space . store_to_eol ]
        in indent . [ Util.del_str "option" . ws . Util.del_str "httpchk" . label "httpchk" .
            ( uri | method . uri . version? )? ] . eol

    let httpclose = bool_option "httpclose"

    let httplog =
        let clf = [ Sep.space . key "clf" ]
        in indent . [ Util.del_str "option" . ws . Util.del_str "httplog" . label "httplog" .
            clf? ] . eol

    let http_proxy = bool_option "http_proxy"

    let independant_streams = bool_option "independant-streams"

    let ldap_check = bool_option "ldap-check"

    let log_health_checks = bool_option "log-health-checks"

    let log_separate_errors = bool_option "log-separate-errors"

    let logasap = bool_option "logasap"

    let mysql_check =
        let user = [ key "user" . Sep.space . store Rx.no_spaces ]
        in indent . [ Util.del_str "option" . ws . Util.del_str "mysql-check" .
            label "mysql_check" . ( Sep.space . user )? ] . eol

    let nolinger = bool_option "nolinger"

    let originalto =
        let except = [ key "except" . Sep.space . store Rx.no_spaces ]
        in let header = [ key "header" . Sep.space . store Rx.no_spaces ]
        in indent . [ Util.del_str "option" . ws . Util.del_str "originalto" . label "originalto" .
            ( Sep.space . except )? . ( Sep.space . header )? ] . eol


    let persist = bool_option "persist"

    let redispatch = bool_option "redispatch"

    let smtpchk =
        let hello = [ label "hello" . store Rx.no_spaces ]
        in let domain = [ label "domain" . store Rx.no_spaces ]
        in indent . [ Util.del_str "option" . ws . Util.del_str "smtpchk" . label "smtpchk" .
            ( Sep.space . hello . Sep.space . domain )? ] . eol

    let socket_stats = bool_option "socket-stats"

    let splice_auto = bool_option "splice-auto"

    let splice_request = bool_option "splice-request"

    let splice_response = bool_option "splice-response"

    let srvtcpka = bool_option "srvtcpka"

    let ssl_hello_chk = bool_option "ssl-hello-chk"

    let tcp_smart_accept = bool_option "tcp-smart-accept"

    let tcp_smart_connect = bool_option "tcp-smart-connect"

    let tcpka = bool_option "tcpka"

    let tcplog = bool_option "tcplog"

    let old_transparent = bool_option "transparent"

    let persist_rdp_cookie = indent . [ Util.del_str "persist" . ws . Util.del_str "rdp-cookie" .
        label "persist-rdp-cookie" . ( Util.del_str "(" . store /[^\)]+/ . Util.del_str ")" )?
        ] . eol

    let rate_limit_sessions = indent . [ Util.del_str "rate-limit" . ws . Util.del_str "sessions" .
        ws . label "rate-limit-sessions" . store /[0-9]+/ ] . eol

    let redirect =
        let location = [ key "location" ]
        in let prefix = [ key "prefix" ]
        in let scheme = [key "scheme"]
        in let to = [ label "to" . store Rx.no_spaces ]
        in let code = [ key "code" . Sep.space . store Rx.no_spaces ]
        in let option_drop_query = [ key "drop-query" ]
        in let option_append_slash = [ key "append-slash" ]
        in let option_set_cookie = [ key "set-cookie" . Sep.space .
            [ label "cookie" . store /[^ \t\n=#]+/ ] .
            ( [ Util.del_str "=" . label "value" . store Rx.no_spaces ] )? ]
        in let option_clear_cookie = [ key "clear-cookie" . Sep.space .
            [ label "cookie" . store Rx.no_spaces ] ]
        in let options = (option_drop_query | option_append_slash | option_set_cookie | option_clear_cookie)
        in let option = [ label "options" . options . ( Sep.space . options )* ]
        in let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in indent . [ key "redirect" . Sep.space . ( location | prefix | scheme ) .
            Sep.space . to . ( Sep.space . code )? . ( Sep.space . option )? .
            ( Sep.space . cond )? ] . eol

    let reqadd = kv_option "reqadd"

    let reqallow = kv_option "reqallow"

    let reqiallow = kv_option "reqiallow"

    let reqdel = kv_option "reqdel"

    let reqidel = kv_option "reqidel"

    let reqdeny = kv_option "reqdeny"

    let reqideny = kv_option "reqideny"

    let reqpass = kv_option "reqpass"

    let reqipass = kv_option "reqipass"

    let reqrep = kv_option "reqrep"

    let reqirep = kv_option "reqirep"

    let reqtarpit = kv_option "reqtarpit"

    let reqitarpit = kv_option "reqitarpit"

    let retries = kv_option "retries"

    let rspadd = kv_option "rspadd"

    let rspdel = kv_option "rspdel"

    let rspidel = kv_option "rspidel"

    let rspdeny = kv_option "rspdeny"

    let rspideny = kv_option "rspideny"

    let rsprep = kv_option "rsprep"

    let rspirep = kv_option "rspirep"

    (* XXX server *)


    let srvtimeout = kv_option "srvtimeout"

    let stats_admin =
        let cond = [ key /if|unless/ . Sep.space . store Rx.space_in ]
        in indent . [ Util.del_str "stats" . ws . Util.del_str "admin" . label "stats_admin" .
            Sep.space . cond ] . eol

    let stats_auth =
        let user = [ label "user" . store /[^ \t\n:#]+/ ]
        in let passwd = [ label "passwd" . store word ]
        in indent . [ Util.del_str "stats" . ws . Util.del_str "auth" . label "stats_auth" .
            Sep.space . user . Util.del_str ":" . passwd ] . eol

    let stats_enable = indent . [ Util.del_str "stats" . ws . Util.del_str "enable" .
        label "stats_enable" ] . eol

    let stats_hide_version = indent . [ Util.del_str "stats" . ws . Util.del_str "hide-version" .
        label "stats_hide_version" ] . eol

    let stats_http_request =
        let allow = [ key "allow" ]
        in let deny = [ key "deny" ]
        in let realm = [ key "realm" . Sep.space . store Rx.no_spaces ]
        in let auth = [ key "auth" . ( Sep.space . realm )? ]
        in let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in indent . [ Util.del_str "stats" . ws . Util.del_str "http-request" .
            label "stats_http_request" . Sep.space . ( allow | deny | auth ) .
            ( Sep.space . cond )? ] . eol

    let stats_realm = indent . [ Util.del_str "stats" . ws . Util.del_str "realm" .
        label "stats_realm" . Sep.space . store_to_eol ] . eol

    let stats_refresh = indent . [ Util.del_str "stats" . ws . Util.del_str "refresh" .
        label "stats_refresh" . Sep.space . store word ] . eol

    let stats_scope = indent . [ Util.del_str "stats" . ws . Util.del_str "scope" .
        label "stats_scope" . Sep.space . store word ] . eol

    let stats_show_desc =
        let desc = [ label "description" . store_to_eol ]
        in indent . [ Util.del_str "stats" . ws . Util.del_str "show-desc" .
            label "stats_show_desc" . ( Sep.space . desc )? ] . eol

    let stats_show_legends = indent . [ Util.del_str "stats" . ws . Util.del_str "show-legends" .
        label "stats_show_legends" ] . eol

    let stats_show_node =
        let node = [ label "node" . store_to_eol ]
        in indent . [ Util.del_str "stats" . ws . Util.del_str "show-node" .
            label "stats_show_node" . ( Sep.space . node )? ] . eol

    let stats_uri = indent . [ Util.del_str "stats" . ws . Util.del_str "uri" .
        label "stats_uri" . Sep.space . store_to_eol ] . eol

    let stick_match =
        let table = [ key "table" . Sep.space . store Rx.no_spaces ]
        in let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in let pattern = [ label "pattern" . store Rx.no_spaces ]
        in indent . [ Util.del_str "stick" . ws . Util.del_str "match" . label "stick_match" .
            Sep.space . pattern . ( Sep.space . table )? .
            ( Sep.space . cond )? ] . eol

    let stick_on =
        let table = [ key "table" . Sep.space . store Rx.no_spaces ]
        in let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in let pattern = [ label "pattern" . store Rx.no_spaces ]
        in indent . [ Util.del_str "stick" . ws . Util.del_str "on" . label "stick_on" .
            Sep.space . pattern . ( Sep.space . table )? .
            ( Sep.space . cond )? ] . eol

    let stick_store_request =
        let table = [ key "table" . Sep.space . store Rx.no_spaces ]
        in let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in let pattern = [ label "pattern" . store Rx.no_spaces ]
        in indent . [ Util.del_str "stick" . ws . Util.del_str "store-request" .
            label "stick_store_request" . Sep.space . pattern .
            ( Sep.space . table )? . ( Sep.space . cond )? ] . eol

    let stick_table =
        let type_ip = [ key "type" . Sep.space . store "ip" ]
        in let type_integer = [ key "type" . Sep.space . store "integer" ]
        in let len = [ key "len" . Sep.space . store Rx.no_spaces ]
        in let type_string = [ key "type" . Sep.space . store "string" .
            ( Sep.space . len )? ]
        in let type = ( type_ip | type_integer | type_string )
        in let size = [ key "size" . Sep.space . store Rx.no_spaces ]
        in let expire = [ key "expire" . Sep.space . store Rx.no_spaces ]
        in let nopurge = [ key "nopurge" ]
        in indent . [ key "stick-table" . Sep.space . type . Sep.space .
            size . ( Sep.space . expire )? . ( Sep.space . nopurge )? ] .
            eol

    let tcp_request_content_accept =
        let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in indent . [ Util.del_str "tcp-request content accept" .
            label "tcp_request_content_accept" . ( Sep.space . cond )? ] .
            eol

    let tcp_request_content_reject =
        let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in indent . [ Util.del_str "tcp-request content reject" .
            label "tcp_request_content_reject" . ( Sep.space . cond )? ] .
            eol

    let tcp_request_inspect_delay = indent .
        [ Util.del_str "tcp-request" . ws . Util.del_str "inspect-delay" .
            label "tcp_request_inspect_delay" . Sep.space . store_to_eol ] .
        eol

    let timeout_check = indent . [ Util.del_str "timeout" . ws . Util.del_str "check" .
        label "timeout_check" . Sep.space . store_to_eol ] . eol

    let timeout_client = indent . [ Util.del_str "timeout" . ws . Util.del_str "client" .
        label "timeout_client" . Sep.space . store_to_eol ] . eol

    let timeout_clitimeout = indent . [ Util.del_str "timeout" . ws . Util.del_str "clitimeout" .
        label "timeout_clitimeout" . Sep.space . store_to_eol ] . eol

    let timeout_connect = indent . [ Util.del_str "timeout" . ws . Util.del_str "connect" .
        label "timeout_connect" . Sep.space . store_to_eol ] . eol

    let timeout_contimeout = indent . [ Util.del_str "timeout" . ws . Util.del_str "contimeout" .
        label "timeout_contimeout" . Sep.space . store_to_eol ] . eol

    let timeout_http_keep_alive = indent . [ Util.del_str "timeout" . ws . Util.del_str "http-keep-alive" .
        label "timeout_http_keep_alive" . Sep.space . store_to_eol ] . eol

    let timeout_http_request = indent . [ Util.del_str "timeout" . ws . Util.del_str "http-request" .
        label "timeout_http_request" . Sep.space . store_to_eol ] . eol

    let timeout_queue = indent . [ Util.del_str "timeout" . ws . Util.del_str "queue" .
        label "timeout_queue" . Sep.space . store_to_eol ] . eol

    let timeout_server = indent . [ Util.del_str "timeout" . ws . Util.del_str "server" .
        label "timeout_server" . Sep.space . store_to_eol ] . eol

    let timeout_srvtimeout = indent . [ Util.del_str "timeout" . ws . Util.del_str "srvtimeout" .
        label "timeout_srvtimeout" . Sep.space . store_to_eol ] . eol

    let timeout_tarpit = indent . [ Util.del_str "timeout" . ws . Util.del_str "tarpit" .
        label "timeout_tarpit" . Sep.space . store_to_eol ] . eol

    let transparent = simple_option "transparent"

    let use_backend =
        let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in indent . [ key "use_backend" . Sep.space . store Rx.no_spaces .
        Sep.space . cond ] . eol

    let unique_id_format = indent . [ key "unique-id-format" .
        Sep.space . store_to_eol ] . eol

    let unique_id_header = indent . [ key "unique-id-header" .
        Sep.space . store_to_eol ] . eol

    let use_server =
        let cond = [ key /if|unless/ . Sep.space . store_to_eol ]
        in indent . [ key "use-server" . Sep.space . store Rx.no_spaces .
            Sep.space . cond  ] . eol

    (*************************************************************************
      GLOBAL SECTION
     *************************************************************************)
    let global_simple_opts = "daemon" | "noepoll" | "nokqueue" | "nopoll" |
        "nosplice" | "nogetaddrinfo" | "tune.ssl.force-private-cache" |
        "debug" | "quiet"

    let global_kv_opts = "ca-base" | "chroot" | "crt-base" | "gid" | "group" |
        "log-send-hostname" | "nbproc" | "pidfile" | "uid" | "ulimit-n" |
        "user" | "ssl-server-verify" | "node" | "description" |
        "max-spread-checks" | "maxconn" | "maxconnrate" |
        "maxcomprate" | "maxcompcpuusage" | "maxpipes" | "maxsessrate" |
        "maxsslconn" | "maxsslrate" | "spread-checks" | "tune.bufsize" |
        "tune.chksize" | "tune.comp.maxlevel" | "tune.http.cookielen" |
        "tune.http.maxhdr" | "tune.idletimer" | "tune.maxaccept" |
        "tune.maxpollevents" | "tune.maxrewrite" | "tune.pipesize" |
        "tune.rcvbuf.client" | "tune.rcvbuf.server" | "tune.sndbuf.client" |
        "tune.sndbuf.server" | "tune.ssl.cachesize" | "tune.ssl.lifetime" |
        "tune.ssl.maxrecord" | "tune.ssl.default-dh-param" |
        "tune.zlib.memlevel" | "tune.zlib.windowsize"

    let stats_bind_process = indent . [ Util.del_str "stats" . ws . Util.del_str "bind-process" .
        label "stats_bind-process" . Sep.space . store_to_eol ] . eol

    let unix_bind =
        let kv (r:regexp) = [ key r . Sep.space . store Rx.no_spaces ]
        in indent . [ key "unix-bind" . ( Sep.space . kv "prefix") ? .
            ( Sep.space . kv "mode") ? . ( Sep.space . kv "user") ? .
            ( Sep.space . kv "uid") ? . ( Sep.space . kv "group") ? .
            ( Sep.space . kv "gid") ? ] . eol


    let global = [ key "global" . eol .
        (simple_option global_simple_opts | kv_or_simple global_kv_opts | stats |
        log_opt | unix_bind | stats_bind_process | empty ) * ]


    (*option for future compatibility. It's essentially a fallback to simple option form*)

    let common_option = kv_or_simple /[^# \n\t\/]+/

    (*************************************************************************
      LISTEN SECTION
     *************************************************************************)


    let proxy_options = (
        acl |
        appsession |
        backlog |
        balance |
        bind |
        bind_process |
        block |
        capture_cookie |
        capture_request_header |
        capture_response_header |
        clitimeout |
        contimeout |
        cookie |
        default_backend |
        disabled |
        dispatch |
        enabled |
        errorfile |
        errorloc |
        errorloc302 |
        errorloc303 |
        force_persist |
        fullconn |
        grace |
        hash_type |
        http_check_disable_on_404 |
        http_check_expect |
        http_check_send_state |
        http_request |
        http_send_name_header |
        id |
        ignore_persist |
        log |
        maxconn |
        mode |
        monitor_fail |
        monitor_net |
        monitor_uri |
        abortonclose |
        accept_invalid_http_request |
        accept_invalid_http_response |
        allbackups |
        checkcache |
        clitcpka |
        contstats |
        default_server |
        dontlog_normal |
        dontlognull |
        forceclose |
        forwardfor |
        http_no_delay |
        http_pretend_keepalive |
        http_server_close |
        http_use_proxy_header |
        httpchk |
        httpclose |
        httplog |
        http_proxy |
        independant_streams |
        ldap_check |
        log_health_checks |
        log_separate_errors |
        logasap |
        mysql_check |
        nolinger |
        originalto |
        persist |
        redispatch |
        smtpchk |
        socket_stats |
        splice_auto |
        splice_request |
        splice_response |
        srvtcpka |
        ssl_hello_chk |
        tcp_smart_accept |
        tcp_smart_connect |
        tcpka |
        tcplog |
        old_transparent |
        persist_rdp_cookie |
        rate_limit_sessions |
        redirect |
        reqadd |
        reqallow |
        reqiallow |
        reqdel |
        reqidel |
        reqdeny |
        reqideny |
        reqpass |
        reqipass |
        reqrep |
        reqirep |
        reqtarpit |
        reqitarpit |
        retries |
        rspadd |
        rspdel |
        rspidel |
        rspdeny |
        rspideny |
        rsprep |
        rspirep |
        server |
        srvtimeout |
        stats_admin |
        stats_auth |
        stats_enable |
        stats_hide_version |
        stats_http_request |
        stats_realm |
        stats_refresh |
        stats_scope |
        stats_show_desc |
        stats_show_legends |
        stats_show_node |
        stats_uri |
        stick_match |
        stick_on |
        stick_store_request |
        stick_table |
        tcp_request_content_accept |
        tcp_request_content_reject |
        tcp_request_inspect_delay |
        timeout_check |
        timeout_client |
        timeout_clitimeout |
        timeout_connect |
        timeout_contimeout |
        timeout_http_keep_alive |
        timeout_http_request |
        timeout_queue |
        timeout_server |
        timeout_srvtimeout |
        timeout_tarpit |
        transparent |
        use_backend |
        unique_id_format |
        unique_id_header |
        use_server |
        common_option)

    let listen =
        let name = [ label "name" . store_to_ws ] in
        [ key "listen" . Sep.space . name .
        eol . (proxy_options | empty)*]

    (*************************************************************************
      BACKEND SECTION
     *************************************************************************)

    let backend =
        let name = [ label "name" . store_to_ws ] in
        [ key "backend" . Sep.space . name . eol .
        (proxy_options | empty)*]

    (*************************************************************************
      FRONTEND SECTION
     *************************************************************************)

    let frontend =
        let name = [ label "name" . store_to_ws ] in
        [ key "frontend" . Sep.space . name . eol .
        (proxy_options | empty)*]

    (*************************************************************************
      DEFAULTS SECTION
     *************************************************************************)

    let defaults =
        [ key "defaults" . eol .
        (proxy_options | empty)*]


    (*************************************************************************)

    let lns = empty * . (optional_indent . (global | defaults | listen | backend | frontend | userlist)) *

    let xfm = transform lns (incl "/etc/haproxy/haproxy.cfg")
