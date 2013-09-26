# WARNING: this file is generated, do not edit
# generated on Thu Sep 12 15:08:15 2013
# 01: /usr/lib64/perl5/vendor_perl/Apache/TestConfig.pm:961
# 02: /usr/lib64/perl5/vendor_perl/Apache/TestConfig.pm:979
# 03: /usr/lib64/perl5/vendor_perl/Apache/TestConfig.pm:1878
# 04: /usr/lib64/perl5/vendor_perl/Apache/TestRun.pm:503
# 05: /usr/lib64/perl5/vendor_perl/Apache/TestRun.pm:713
# 06: /usr/lib64/perl5/vendor_perl/Apache/TestRun.pm:713
# 07: /home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/TEST:18

package apache_test_config;

sub new {
    bless( {
         'verbose' => 1,
         'hostport' => 'localhost.localdomain:8529',
         'clean_level' => 1,
         'postamble' => [
                          '<IfModule mod_mime.c>
    TypesConfig "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/conf/mime.types"
</IfModule>
',
                          'Include "/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/conf/extra.conf"
',
                          '
'
                        ],
         'mpm' => 'prefork',
         'inc' => [],
         'APXS' => '/usr/sbin/apxs',
         '_apxs' => {
                      'LIBEXECDIR' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules',
                      'SYSCONFDIR' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/conf',
                      'TARGET' => 'httpd',
                      'BINDIR' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/bin',
                      'PREFIX' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork',
                      'SBINDIR' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/bin'
                    },
         'save' => 1,
         'vhosts' => {},
         'httpd_basedir' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork',
         'server' => bless( {
                              'run' => bless( {
                                                'conf_opts' => {
                                                                 'verbose' => 1,
                                                                 'save' => 1,
                                                                 'apxs' => '/usr/sbin/apxs',
                                                                 'httpd' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/bin/httpd'
                                                               },
                                                'test_config' => $VAR1,
                                                'tests' => [],
                                                'opts' => {
                                                            'verbose' => 1,
                                                            'stop-httpd' => 1,
                                                            'breakpoint' => [],
                                                            'start-httpd' => 1,
                                                            'postamble' => [],
                                                            'preamble' => [],
                                                            'run-tests' => 1,
                                                            'req_args' => {},
                                                            'header' => {}
                                                          },
                                                'argv' => [],
                                                'server' => $VAR1->{'server'}
                                              }, 'Apache::TestRun' ),
                              'port_counter' => 8529,
                              'mpm' => 'prefork',
                              'version' => 'Apache/2.2.25-dev',
                              'rev' => '2',
                              'name' => 'localhost.localdomain:8529',
                              'config' => $VAR1
                            }, 'Apache::TestServer' ),
         'postamble_hooks' => [
                                sub { "DUMMY" }
                              ],
         'inherit_config' => {
                               'ServerRoot' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork',
                               'ServerAdmin' => 'you@example.com',
                               'TypesConfig' => 'conf/mime.types',
                               'DocumentRoot' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/htdocs',
                               'LoadModule' => [
                                                 [
                                                   'authn_file_module',
                                                   'modules/mod_authn_file.so'
                                                 ],
                                                 [
                                                   'authn_dbm_module',
                                                   'modules/mod_authn_dbm.so'
                                                 ],
                                                 [
                                                   'authn_anon_module',
                                                   'modules/mod_authn_anon.so'
                                                 ],
                                                 [
                                                   'authn_dbd_module',
                                                   'modules/mod_authn_dbd.so'
                                                 ],
                                                 [
                                                   'authn_default_module',
                                                   'modules/mod_authn_default.so'
                                                 ],
                                                 [
                                                   'authz_host_module',
                                                   'modules/mod_authz_host.so'
                                                 ],
                                                 [
                                                   'authz_groupfile_module',
                                                   'modules/mod_authz_groupfile.so'
                                                 ],
                                                 [
                                                   'authz_user_module',
                                                   'modules/mod_authz_user.so'
                                                 ],
                                                 [
                                                   'authz_dbm_module',
                                                   'modules/mod_authz_dbm.so'
                                                 ],
                                                 [
                                                   'authz_owner_module',
                                                   'modules/mod_authz_owner.so'
                                                 ],
                                                 [
                                                   'authz_default_module',
                                                   'modules/mod_authz_default.so'
                                                 ],
                                                 [
                                                   'auth_basic_module',
                                                   'modules/mod_auth_basic.so'
                                                 ],
                                                 [
                                                   'auth_digest_module',
                                                   'modules/mod_auth_digest.so'
                                                 ],
                                                 [
                                                   'dbd_module',
                                                   'modules/mod_dbd.so'
                                                 ],
                                                 [
                                                   'dumpio_module',
                                                   'modules/mod_dumpio.so'
                                                 ],
                                                 [
                                                   'reqtimeout_module',
                                                   'modules/mod_reqtimeout.so'
                                                 ],
                                                 [
                                                   'ext_filter_module',
                                                   'modules/mod_ext_filter.so'
                                                 ],
                                                 [
                                                   'include_module',
                                                   'modules/mod_include.so'
                                                 ],
                                                 [
                                                   'filter_module',
                                                   'modules/mod_filter.so'
                                                 ],
                                                 [
                                                   'substitute_module',
                                                   'modules/mod_substitute.so'
                                                 ],
                                                 [
                                                   'deflate_module',
                                                   'modules/mod_deflate.so'
                                                 ],
                                                 [
                                                   'log_config_module',
                                                   'modules/mod_log_config.so'
                                                 ],
                                                 [
                                                   'log_forensic_module',
                                                   'modules/mod_log_forensic.so'
                                                 ],
                                                 [
                                                   'logio_module',
                                                   'modules/mod_logio.so'
                                                 ],
                                                 [
                                                   'env_module',
                                                   'modules/mod_env.so'
                                                 ],
                                                 [
                                                   'mime_magic_module',
                                                   'modules/mod_mime_magic.so'
                                                 ],
                                                 [
                                                   'cern_meta_module',
                                                   'modules/mod_cern_meta.so'
                                                 ],
                                                 [
                                                   'expires_module',
                                                   'modules/mod_expires.so'
                                                 ],
                                                 [
                                                   'headers_module',
                                                   'modules/mod_headers.so'
                                                 ],
                                                 [
                                                   'ident_module',
                                                   'modules/mod_ident.so'
                                                 ],
                                                 [
                                                   'usertrack_module',
                                                   'modules/mod_usertrack.so'
                                                 ],
                                                 [
                                                   'unique_id_module',
                                                   'modules/mod_unique_id.so'
                                                 ],
                                                 [
                                                   'setenvif_module',
                                                   'modules/mod_setenvif.so'
                                                 ],
                                                 [
                                                   'version_module',
                                                   'modules/mod_version.so'
                                                 ],
                                                 [
                                                   'proxy_module',
                                                   'modules/mod_proxy.so'
                                                 ],
                                                 [
                                                   'proxy_connect_module',
                                                   'modules/mod_proxy_connect.so'
                                                 ],
                                                 [
                                                   'proxy_ftp_module',
                                                   'modules/mod_proxy_ftp.so'
                                                 ],
                                                 [
                                                   'proxy_http_module',
                                                   'modules/mod_proxy_http.so'
                                                 ],
                                                 [
                                                   'proxy_scgi_module',
                                                   'modules/mod_proxy_scgi.so'
                                                 ],
                                                 [
                                                   'proxy_ajp_module',
                                                   'modules/mod_proxy_ajp.so'
                                                 ],
                                                 [
                                                   'proxy_balancer_module',
                                                   'modules/mod_proxy_balancer.so'
                                                 ],
                                                 [
                                                   'mime_module',
                                                   'modules/mod_mime.so'
                                                 ],
                                                 [
                                                   'dav_module',
                                                   'modules/mod_dav.so'
                                                 ],
                                                 [
                                                   'status_module',
                                                   'modules/mod_status.so'
                                                 ],
                                                 [
                                                   'autoindex_module',
                                                   'modules/mod_autoindex.so'
                                                 ],
                                                 [
                                                   'asis_module',
                                                   'modules/mod_asis.so'
                                                 ],
                                                 [
                                                   'info_module',
                                                   'modules/mod_info.so'
                                                 ],
                                                 [
                                                   'cgi_module',
                                                   'modules/mod_cgi.so'
                                                 ],
                                                 [
                                                   'dav_fs_module',
                                                   'modules/mod_dav_fs.so'
                                                 ],
                                                 [
                                                   'vhost_alias_module',
                                                   'modules/mod_vhost_alias.so'
                                                 ],
                                                 [
                                                   'negotiation_module',
                                                   'modules/mod_negotiation.so'
                                                 ],
                                                 [
                                                   'dir_module',
                                                   'modules/mod_dir.so'
                                                 ],
                                                 [
                                                   'imagemap_module',
                                                   'modules/mod_imagemap.so'
                                                 ],
                                                 [
                                                   'actions_module',
                                                   'modules/mod_actions.so'
                                                 ],
                                                 [
                                                   'speling_module',
                                                   'modules/mod_speling.so'
                                                 ],
                                                 [
                                                   'userdir_module',
                                                   'modules/mod_userdir.so'
                                                 ],
                                                 [
                                                   'alias_module',
                                                   'modules/mod_alias.so'
                                                 ],
                                                 [
                                                   'rewrite_module',
                                                   'modules/mod_rewrite.so'
                                                 ]
                                               ],
                               'LoadFile' => []
                             },
         'cmodules_disabled' => {},
         'preamble_hooks' => [
                               sub { "DUMMY" }
                             ],
         'preamble' => [
                         '<IfModule !mod_authn_file.c>
    LoadModule authn_file_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_file.so"
</IfModule>
',
                         '<IfModule !mod_authn_dbm.c>
    LoadModule authn_dbm_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_dbm.so"
</IfModule>
',
                         '<IfModule !mod_authn_anon.c>
    LoadModule authn_anon_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_anon.so"
</IfModule>
',
                         '<IfModule !mod_authn_dbd.c>
    LoadModule authn_dbd_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_dbd.so"
</IfModule>
',
                         '<IfModule !mod_authn_default.c>
    LoadModule authn_default_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_default.so"
</IfModule>
',
                         '<IfModule !mod_authz_host.c>
    LoadModule authz_host_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_host.so"
</IfModule>
',
                         '<IfModule !mod_authz_groupfile.c>
    LoadModule authz_groupfile_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_groupfile.so"
</IfModule>
',
                         '<IfModule !mod_authz_user.c>
    LoadModule authz_user_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_user.so"
</IfModule>
',
                         '<IfModule !mod_authz_dbm.c>
    LoadModule authz_dbm_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_dbm.so"
</IfModule>
',
                         '<IfModule !mod_authz_owner.c>
    LoadModule authz_owner_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_owner.so"
</IfModule>
',
                         '<IfModule !mod_authz_default.c>
    LoadModule authz_default_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_default.so"
</IfModule>
',
                         '<IfModule !mod_auth_basic.c>
    LoadModule auth_basic_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_auth_basic.so"
</IfModule>
',
                         '<IfModule !mod_auth_digest.c>
    LoadModule auth_digest_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_auth_digest.so"
</IfModule>
',
                         '<IfModule !mod_dbd.c>
    LoadModule dbd_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dbd.so"
</IfModule>
',
                         '<IfModule !mod_dumpio.c>
    LoadModule dumpio_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dumpio.so"
</IfModule>
',
                         '<IfModule !mod_reqtimeout.c>
    LoadModule reqtimeout_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_reqtimeout.so"
</IfModule>
',
                         '<IfModule !mod_ext_filter.c>
    LoadModule ext_filter_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_ext_filter.so"
</IfModule>
',
                         '<IfModule !mod_include.c>
    LoadModule include_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_include.so"
</IfModule>
',
                         '<IfModule !mod_filter.c>
    LoadModule filter_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_filter.so"
</IfModule>
',
                         '<IfModule !mod_substitute.c>
    LoadModule substitute_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_substitute.so"
</IfModule>
',
                         '<IfModule !mod_deflate.c>
    LoadModule deflate_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_deflate.so"
</IfModule>
',
                         '<IfModule !mod_log_config.c>
    LoadModule log_config_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_log_config.so"
</IfModule>
',
                         '<IfModule !mod_log_forensic.c>
    LoadModule log_forensic_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_log_forensic.so"
</IfModule>
',
                         '<IfModule !mod_logio.c>
    LoadModule logio_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_logio.so"
</IfModule>
',
                         '<IfModule !mod_env.c>
    LoadModule env_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_env.so"
</IfModule>
',
                         '<IfModule !mod_mime_magic.c>
    LoadModule mime_magic_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_mime_magic.so"
</IfModule>
',
                         '<IfModule !mod_cern_meta.c>
    LoadModule cern_meta_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_cern_meta.so"
</IfModule>
',
                         '<IfModule !mod_expires.c>
    LoadModule expires_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_expires.so"
</IfModule>
',
                         '<IfModule !mod_headers.c>
    LoadModule headers_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_headers.so"
</IfModule>
',
                         '<IfModule !mod_ident.c>
    LoadModule ident_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_ident.so"
</IfModule>
',
                         '<IfModule !mod_usertrack.c>
    LoadModule usertrack_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_usertrack.so"
</IfModule>
',
                         '<IfModule !mod_unique_id.c>
    LoadModule unique_id_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_unique_id.so"
</IfModule>
',
                         '<IfModule !mod_setenvif.c>
    LoadModule setenvif_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_setenvif.so"
</IfModule>
',
                         '<IfModule !mod_version.c>
    LoadModule version_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_version.so"
</IfModule>
',
                         '<IfModule !mod_proxy.c>
    LoadModule proxy_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy.so"
</IfModule>
',
                         '<IfModule !mod_proxy_connect.c>
    LoadModule proxy_connect_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_connect.so"
</IfModule>
',
                         '<IfModule !mod_proxy_ftp.c>
    LoadModule proxy_ftp_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_ftp.so"
</IfModule>
',
                         '<IfModule !mod_proxy_http.c>
    LoadModule proxy_http_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_http.so"
</IfModule>
',
                         '<IfModule !mod_proxy_scgi.c>
    LoadModule proxy_scgi_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_scgi.so"
</IfModule>
',
                         '<IfModule !mod_proxy_ajp.c>
    LoadModule proxy_ajp_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_ajp.so"
</IfModule>
',
                         '<IfModule !mod_proxy_balancer.c>
    LoadModule proxy_balancer_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_balancer.so"
</IfModule>
',
                         '<IfModule !mod_mime.c>
    LoadModule mime_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_mime.so"
</IfModule>
',
                         '<IfModule !mod_dav.c>
    LoadModule dav_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dav.so"
</IfModule>
',
                         '<IfModule !mod_status.c>
    LoadModule status_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_status.so"
</IfModule>
',
                         '<IfModule !mod_autoindex.c>
    LoadModule autoindex_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_autoindex.so"
</IfModule>
',
                         '<IfModule !mod_asis.c>
    LoadModule asis_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_asis.so"
</IfModule>
',
                         '<IfModule !mod_info.c>
    LoadModule info_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_info.so"
</IfModule>
',
                         '<IfModule !mod_cgi.c>
    LoadModule cgi_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_cgi.so"
</IfModule>
',
                         '<IfModule !mod_dav_fs.c>
    LoadModule dav_fs_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dav_fs.so"
</IfModule>
',
                         '<IfModule !mod_vhost_alias.c>
    LoadModule vhost_alias_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_vhost_alias.so"
</IfModule>
',
                         '<IfModule !mod_negotiation.c>
    LoadModule negotiation_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_negotiation.so"
</IfModule>
',
                         '<IfModule !mod_dir.c>
    LoadModule dir_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dir.so"
</IfModule>
',
                         '<IfModule !mod_imagemap.c>
    LoadModule imagemap_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_imagemap.so"
</IfModule>
',
                         '<IfModule !mod_actions.c>
    LoadModule actions_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_actions.so"
</IfModule>
',
                         '<IfModule !mod_speling.c>
    LoadModule speling_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_speling.so"
</IfModule>
',
                         '<IfModule !mod_userdir.c>
    LoadModule userdir_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_userdir.so"
</IfModule>
',
                         '<IfModule !mod_alias.c>
    LoadModule alias_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_alias.so"
</IfModule>
',
                         '<IfModule !mod_rewrite.c>
    LoadModule rewrite_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_rewrite.so"
</IfModule>
',
                         '<IfModule !mod_mime.c>
    LoadModule mime_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_mime.so"
</IfModule>
',
                         '<IfModule !mod_alias.c>
    LoadModule alias_module "/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_alias.so"
</IfModule>
',
                         '
'
                       ],
         'vars' => {
                     'defines' => '',
                     'cgi_module_name' => 'mod_cgi',
                     'conf_dir' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/conf',
                     't_conf_file' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/conf/httpd.conf',
                     't_dir' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t',
                     'cgi_module' => 'mod_cgi.c',
                     'target' => 'httpd',
                     'thread_module' => 'worker.c',
                     'bindir' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/bin',
                     'user' => 'gozer',
                     'access_module_name' => 'mod_authz_host',
                     'auth_module_name' => 'mod_auth_basic',
                     'top_dir' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona',
                     'httpd_conf' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/conf/httpd.conf',
                     'httpd' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/bin/httpd',
                     'scheme' => 'http',
                     'ssl_module_name' => 'mod_ssl',
                     'port' => 8529,
                     'sbindir' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/bin',
                     't_conf' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/conf',
                     'servername' => 'localhost.localdomain',
                     'inherit_documentroot' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/htdocs',
                     'proxy' => 'off',
                     'serveradmin' => 'you@example.com',
                     'remote_addr' => '127.0.0.1',
                     'perlpod' => '/usr/share/perl5/pod',
                     'sslcaorg' => 'asf',
                     'php_module_name' => 'sapi_apache2',
                     'maxclients_preset' => 0,
                     'php_module' => 'sapi_apache2.c',
                     'ssl_module' => 'mod_ssl.c',
                     'auth_module' => 'mod_auth_basic.c',
                     'access_module' => 'mod_authz_host.c',
                     't_logs' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/logs',
                     'minclients' => 1,
                     'maxclients' => 2,
                     'group' => 'gozer',
                     't_pid_file' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/logs/httpd.pid',
                     'apxs' => '/usr/sbin/apxs',
                     'maxclientsthreadedmpm' => 2,
                     'thread_module_name' => 'worker',
                     'documentroot' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/htdocs',
                     'serverroot' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t',
                     'sslca' => '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/conf/ssl/ca',
                     'perl' => '/usr/bin/perl',
                     'src_dir' => undef,
                     'proxyssl_url' => ''
                   },
         'clean' => {
                      'files' => {
                                   '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/htdocs/index.html' => 1,
                                   '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/conf/extra.conf' => 1,
                                   '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/conf/httpd.conf' => 1,
                                   '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/logs/apache_runtime_status.sem' => 1,
                                   '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/conf/apache_test_config.pm' => 1
                                 },
                      'dirs' => {
                                  '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/htdocs' => 1,
                                  '/home/gozer/opt/src/mozilla.org/gozer/mod_authn_persona/t/logs' => 1
                                }
                    },
         'httpd_info' => {
                           'BUILT' => 'Mar 27 2013 18:11:41',
                           'MODULE_MAGIC_NUMBER_MINOR' => '31',
                           'SERVER_MPM' => 'Prefork',
                           'VERSION' => 'Apache/2.2.25-dev (Unix)',
                           'MODULE_MAGIC_NUMBER' => '20051115:31',
                           'MODULE_MAGIC_NUMBER_MAJOR' => '20051115'
                         },
         'modules' => {
                        'mod_include.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_include.so',
                        'mod_headers.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_headers.so',
                        'mod_negotiation.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_negotiation.so',
                        'mod_proxy_ajp.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_ajp.so',
                        'mod_authn_file.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_file.so',
                        'mod_speling.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_speling.so',
                        'mod_authz_user.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_user.so',
                        'mod_proxy_balancer.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_balancer.so',
                        'mod_usertrack.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_usertrack.so',
                        'mod_ident.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_ident.so',
                        'mod_authz_owner.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_owner.so',
                        'mod_cern_meta.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_cern_meta.so',
                        'mod_proxy_connect.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_connect.so',
                        'mod_ext_filter.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_ext_filter.so',
                        'mod_setenvif.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_setenvif.so',
                        'mod_authn_dbm.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_dbm.so',
                        'mod_log_forensic.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_log_forensic.so',
                        'mod_authn_anon.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_anon.so',
                        'mod_authz_host.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_host.so',
                        'mod_dumpio.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dumpio.so',
                        'mod_proxy_http.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_http.so',
                        'mod_unique_id.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_unique_id.so',
                        'mod_proxy_ftp.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_ftp.so',
                        'mod_status.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_status.so',
                        'mod_dav.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dav.so',
                        'mod_log_config.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_log_config.so',
                        'mod_auth_digest.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_auth_digest.so',
                        'mod_asis.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_asis.so',
                        'mod_env.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_env.so',
                        'mod_auth_basic.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_auth_basic.so',
                        'mod_deflate.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_deflate.so',
                        'mod_version.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_version.so',
                        'mod_dbd.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dbd.so',
                        'mod_proxy.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy.so',
                        'mod_dav_fs.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dav_fs.so',
                        'core.c' => 1,
                        'mod_authz_groupfile.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_groupfile.so',
                        'http_core.c' => 1,
                        'mod_dir.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_dir.so',
                        'mod_reqtimeout.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_reqtimeout.so',
                        'mod_filter.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_filter.so',
                        'mod_imagemap.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_imagemap.so',
                        'prefork.c' => 1,
                        'mod_actions.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_actions.so',
                        'mod_cgi.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_cgi.so',
                        'mod_proxy_scgi.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_proxy_scgi.so',
                        'mod_so.c' => 1,
                        'mod_mime_magic.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_mime_magic.so',
                        'mod_expires.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_expires.so',
                        'mod_logio.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_logio.so',
                        'mod_authn_dbd.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_dbd.so',
                        'mod_alias.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_alias.so',
                        'mod_authz_dbm.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_dbm.so',
                        'mod_autoindex.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_autoindex.so',
                        'mod_rewrite.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_rewrite.so',
                        'mod_substitute.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_substitute.so',
                        'mod_authn_default.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authn_default.so',
                        'mod_userdir.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_userdir.so',
                        'mod_mime.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_mime.so',
                        'mod_authz_default.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_authz_default.so',
                        'mod_vhost_alias.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_vhost_alias.so',
                        'mod_info.c' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/modules/mod_info.so'
                      },
         'httpd_defines' => {
                              'SUEXEC_BIN' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork/bin/suexec',
                              'APR_HAS_MMAP' => 1,
                              'APR_HAS_OTHER_CHILD' => 1,
                              'DEFAULT_PIDLOG' => 'logs/httpd.pid',
                              'DYNAMIC_MODULE_LIMIT' => '128',
                              'AP_TYPES_CONFIG_FILE' => 'conf/mime.types',
                              'DEFAULT_SCOREBOARD' => 'logs/apache_runtime_status',
                              'DEFAULT_LOCKFILE' => 'logs/accept.lock',
                              'APR_USE_SYSVSEM_SERIALIZE' => 1,
                              'APR_HAVE_IPV6 (IPv4-mapped addresses enabled)' => 1,
                              'APACHE_MPM_DIR' => 'server/mpm/prefork',
                              'DEFAULT_ERRORLOG' => 'logs/error_log',
                              'APR_HAS_SENDFILE' => 1,
                              'HTTPD_ROOT' => '/home/gozer/opt/apache.org/httpd/2.2.25-dev/prefork',
                              'AP_HAVE_RELIABLE_PIPED_LOGS' => 1,
                              'SERVER_CONFIG_FILE' => 'conf/httpd.conf',
                              'APR_USE_PTHREAD_SERIALIZE' => 1
                            },
         'apache_test_version' => '1.37'
       }, 'Apache::TestConfig' );
}

1;
