package common;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
 $verbose $dry_run $overwrite
 $CA $KRA $OCSP $TKS $RA $TPS
 $config_separator $sums_separator
 $pki_user $pki_group $default_file_permissions $default_exe_permissions
 $default_dir_permissions
 
 set_permissions
 check_for_root_UID 
 get_time_stamp 
 open_logfile close_logfile emit
 is_path_valid 
 copy_file remove_file
 create_subs_directory read_cfg
 create_sums_file find_changes populate_hash_values
 perform_file_actions check_for_customizations
 perform_cs_actions list_values_equal
 find_directory_changes
 );

use File::Find;
use File::Path qw{mkpath rmtree};
use File::Copy;

# Global variables
my %subs_hash = ();

##############################################################
# Global Constants
##############################################################

our $ROOTUID = 0;
our $config_separator = "=";
our $sums_separator   = "  ";
our $default_file_permissions = 00660;
our $default_exe_permissions  = 00770;
our $default_dir_permissions  = 00770;

# Subsystem names
our $CA   = "ca";
our $KRA  = "kra";
our $OCSP = "ocsp";
our $TKS  = "tks";
our $RA   = "ra";
our $TPS  = "tps";

# Template slot constants (RA, TPS)
my $GROUPID                = "GROUPID";
my $HTTPD_CONF             = "HTTPD_CONF";
my $INSTANCE_ID            = "INSTANCE_ID";
my $INSTANCE_ROOT          = "INSTANCE_ROOT";
my $LIB_PREFIX             = "LIB_PREFIX";
my $NSS_CONF               = "NSS_CONF";
my $OBJ_EXT                = "OBJ_EXT";
my $PORT                   = "PORT";
my $PROCESS_ID             = "PROCESS_ID";
my $SECURE_PORT            = "SECURE_PORT";
my $NON_CLIENTAUTH_SECURE_PORT = "NON_CLIENTAUTH_SECURE_PORT";
my $SECURITY_LIBRARIES     = "SECURITY_LIBRARIES";
my $SERVER_NAME            = "SERVER_NAME";
my $SERVER_ROOT            = "SERVER_ROOT";
my $SUBSYSTEM_TYPE         = "SUBSYSTEM_TYPE";
my $SYSTEM_LIBRARIES       = "SYSTEM_LIBRARIES";
my $SYSTEM_USER_LIBRARIES  = "SYSTEM_USER_LIBRARIES";
my $TMP_DIR                = "TMP_DIR";
my $TPS_DIR                = "TPS_DIR";
my $USERID                 = "USERID";
my $FORTITUDE_APACHE       = "FORTITUDE_APACHE";
my $FORTITUDE_DIR          = "FORTITUDE_DIR";
my $FORTITUDE_MODULE       = "FORTITUDE_MODULE";
my $FORTITUDE_LIB_DIR      = "FORTITUDE_LIB_DIR";
my $FORTITUDE_AUTH_MODULES = "FORTITUDE_AUTH_MODULES";
my $FORTITUDE_NSS_MODULES  = "FORTITUDE_NSS_MODULES";

# Template slot constants (CA, KRA, OCSP, TKS)
my $INSTALL_TIME              = "INSTALL_TIME";
my $PKI_AGENT_CLIENTAUTH_SLOT = "PKI_AGENT_CLIENTAUTH";
my $PKI_CERT_DB_PASSWORD_SLOT = "PKI_CERT_DB_PASSWORD";
my $PKI_CFG_PATH_NAME_SLOT    = "PKI_CFG_PATH_NAME";
my $PKI_GROUP_SLOT            = "PKI_GROUP";
my $PKI_INSTANCE_ID_SLOT      = "PKI_INSTANCE_ID";
my $PKI_INSTANCE_PATH_SLOT    = "PKI_INSTANCE_PATH";
my $PKI_INSTANCE_ROOT_SLOT    = "PKI_INSTANCE_ROOT";
my $PKI_MACHINE_NAME_SLOT     = "PKI_MACHINE_NAME";
my $PKI_RANDOM_NUMBER_SLOT    = "PKI_RANDOM_NUMBER";
my $PKI_SECURE_PORT_SLOT      = "PKI_SECURE_PORT";
my $PKI_EE_SECURE_PORT_SLOT   = "PKI_EE_SECURE_PORT";
my $PKI_EE_SECURE_CLIENT_AUTH_PORT_SLOT   = "PKI_EE_SECURE_CLIENT_AUTH_PORT";
my $PKI_AGENT_SECURE_PORT_SLOT = "PKI_AGENT_SECURE_PORT";
my $PKI_ADMIN_SECURE_PORT_SLOT = "PKI_ADMIN_SECURE_PORT";
my $PKI_SERVER_XML_CONF       = "PKI_SERVER_XML_CONF";
my $PKI_SUBSYSTEM_TYPE_SLOT   = "PKI_SUBSYSTEM_TYPE";
my $PKI_UNSECURE_PORT_SLOT    = "PKI_UNSECURE_PORT";
my $PKI_USER_SLOT             = "PKI_USER";
my $TOMCAT_SERVER_PORT_SLOT   = "TOMCAT_SERVER_PORT";
my $PKI_FLAVOR_SLOT           = "PKI_FLAVOR";
my $PKI_SECURITY_MANAGER_SLOT = "PKI_SECURITY_MANAGER";
my $PKI_UNSECURE_PORT_CONNECTOR_NAME_SLOT     = "PKI_UNSECURE_PORT_CONNECTOR_NAME";
my $PKI_SECURE_PORT_CONNECTOR_NAME_SLOT       = "PKI_SECURE_PORT_CONNECTOR_NAME";
my $PKI_ADMIN_SECURE_PORT_CONNECTOR_NAME_SLOT = "PKI_ADMIN_SECURE_PORT_CONNECTOR_NAME";
my $PKI_EE_SECURE_PORT_CONNECTOR_NAME_SLOT    = "PKI_EE_SECURE_PORT_CONNECTOR_NAME";
my $PKI_EE_SECURE_CLIENT_AUTH_PORT_CONNECTOR_NAME_SLOT    = "PKI_EE_SECURE_CLIENT_AUTH_PORT_CONNECTOR_NAME";
my $PKI_UNSECURE_PORT_COMMENT_SERVER_SLOT     = "PKI_UNSECURE_PORT_SERVER_COMMENT";
my $PKI_SECURE_PORT_COMMENT_SERVER_SLOT       = "PKI_SECURE_PORT_SERVER_COMMENT";
my $PKI_ADMIN_SECURE_PORT_COMMENT_SERVER_SLOT = "PKI_ADMIN_SECURE_PORT_SERVER_COMMENT";
my $PKI_EE_SECURE_PORT_COMMENT_SERVER_SLOT    = "PKI_EE_SECURE_PORT_SERVER_COMMENT";
my $PKI_EE_SECURE_CLIENT_AUTH_PORT_COMMENT_SERVER_SLOT = "PKI_EE_SECURE_CLIENT_AUTH_PORT_SERVER_COMMENT";
my $PKI_OPEN_SEPARATE_PORTS_COMMENT_SERVER_SLOT  = "PKI_OPEN_SEPARATE_PORTS_SERVER_COMMENT";
my $PKI_CLOSE_SEPARATE_PORTS_COMMENT_SERVER_SLOT = "PKI_CLOSE_SEPARATE_PORTS_SERVER_COMMENT";
my $PKI_OPEN_SEPARATE_PORTS_COMMENT_WEB_SLOT  = "PKI_OPEN_SEPARATE_PORTS_WEB_COMMENT";
my $PKI_CLOSE_SEPARATE_PORTS_COMMENT_WEB_SLOT = "PKI_CLOSE_SEPARATE_PORTS_WEB_COMMENT";
my $PKI_UNSECURE_PORT_NAME      = "Unsecure";
my $PKI_AGENT_SECURE_PORT_NAME  = "Agent";
my $PKI_ADMIN_SECURE_PORT_NAME  = "Admin";
my $PKI_EE_SECURE_PORT_NAME     = "EE";
my $PKI_EE_SECURE_CLIENT_AUTH_PORT_NAME     = "EEClientAuth";
my $PKI_SECURE_PORT_NAME        = "Secure";
my $PKI_UNUSED_SECURE_PORT_NAME = "Unused";
my $PKI_UNSECURE_SEPARATE_PORTS_COMMENT = "<!-- Port Separation:  Unsecure Port Connector -->";
my $PKI_AGENT_SECURE_SEPARATE_PORTS_COMMENT = "<!-- Port Separation:  Agent Secure Port Connector -->";
my $PKI_ADMIN_SECURE_SEPARATE_PORTS_COMMENT = "<!-- Port Separation:  Admin Secure Port Connector -->";
my $PKI_EE_SECURE_SEPARATE_PORTS_COMMENT = "<!-- Port Separation:  EE Secure Port Connector -->";
my $PKI_EE_SECURE_CLIENT_AUTH_SEPARATE_PORTS_COMMENT = "<!-- Port Separation:  EE Secure Client Auth Port Connector -->";
my $PKI_UNSECURE_SHARED_PORTS_COMMENT = "<!-- Shared Ports:  Unsecure Port Connector -->";
my $PKI_SECURE_SHARED_PORTS_COMMENT = "<!-- Shared Ports:  Agent, EE, and Admin Secure Port Connector -->";
my $PKI_OPEN_COMMENT          = "<!--";
my $PKI_CLOSE_COMMENT         = "-->";
my $PKI_WEBAPPS_NAME          = "PKI_WEBAPPS_NAME";

##############################################################
# Local Variables
##############################################################

# "logging" parameters
my $logfd = undef;
my $logfile_path = undef;

##############################################################
# Global Variables
##############################################################

# Whether or not to do verbose mode
our $verbose = 0;

# Controls whether actions are executed (dry_run == false)
# or if actions are only reported (dry_run == true).
our $dry_run = 0;

# Controls whether customized files are backed up and overwritten  (overwrite == true)
# or just reported (overwrite == false).
my $overwrite = 0;

our $pki_user  = "pkiuser";
our $pki_group = "pkiuser";


##############################################################
# Utility Subroutines
##############################################################

# no args
# return time stamp
sub get_time_stamp
{
    my ($sec, $min, $hour, $mday,
        $mon, $year, $wday, $yday, $isdst) = localtime(time);

    my $stamp = sprintf "%4d-%02d-%02d %02d:%02d:%02d",
                        $year+1900, $mon+1, $mday, $hour, $min, $sec;

    return $stamp;
}

# no return value
sub emit
{
    my ($string, $type) = @_;

    my $force_emit = 0;
    my $log_entry = "";

    $type = "debug" if !defined($type);

    if ($type eq "error" || $type eq "warning" || $type eq "info") {
        $force_emit = 1;
    }

    return if !$string;

    chomp($string);
    my $stamp = get_time_stamp();

    if ($verbose || $force_emit) {
        # print to stdout
        if ($type ne "log") {
            print(STDERR "[$type] $string\n");
        }
    }

    # If a log file exists, write all types
    # ("debug", "error", "info", or "log")
    # to this specified log file
    if (defined($logfd)) {
        $log_entry = "[$stamp] [$type] $string\n";
        $logfd->print($log_entry);
    }

    return;
}

# no args
# return 1 - success, or
# return 0 - failure
sub check_for_root_UID
{
    my $result = 0;

    if (($< != $ROOTUID) && ($> != $ROOTUID)) {
        emit("This script must be run as root!\n", "error");
        $result = 0;
    } else {
        # Success -- running script as root
        $result = 1;
    }

    return $result;
}

# Return 1 if success, 0 if failure
sub remove_file
{
    my ($path) = @_;
    my $result = 0;

    emit(sprintf("remove_file(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    if (!unlink($path)) {
        emit("remove_file(): failed to remove file \"$path\" ($!)\n", "error");
        return 0;
    }

    return 1;
}

# Return 1 if success, 0 if failure
sub copy_file
{
    my ($src_path, $dst_path, $permissions, $owner, $group) = @_;

    emit(sprintf("copy_file(%s, %s, %s, %s, %s)\n",
                 $src_path, $dst_path,
                 defined($permissions) ? sprintf("%o", $permissions) : "",
                 $owner, $group), "debug");

    if (!$dry_run) {
        if (!copy($src_path, $dst_path)) {
            emit("copy_file(): \"$src_path\" => \"$dst_path\" ($!)\n", "error");
            return 0;
        }
    }

    if (defined($permissions)) {
        return 0 if !set_permissions($dst_path, $permissions);
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($dst_path, $owner, $group);
    }

    return 1;
}

# set_owner_group(path_glob, owner, group)
# Return 1 if success, 0 if failure
sub set_owner_group
{
    my ($path_glob, $owner, $group) = @_;
    my (@paths, $errstr, $result, $count);
    my ($uid, $gid);

    $errstr = undef;
    $count = 0;
    $result = 1;

    emit(sprintf("set_owner_group(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    $uid   = getpwnam($owner);
    $gid   = getgrnam($group);
    @paths = glob($path_glob);

    if (($count = chown($uid, $gid, @paths)) != @paths) {
        $errstr = "$!";
        $result = 0;
        emit(sprintf("failed to set ownership (%s) on \"%s\" => (%s), %d out of %d failed, \"%s\"\n",
                     "${owner}:${group}", $path_glob, "@paths", @paths - $count, @paths+0, $errstr), 'error');
    }
    return $result;
}

# arg0 file name
# return buffer containing file contents
# - needed as perl-File-Slurp is not in RHEL5
sub read_file
{
   my ($fname) = @_;
   my $buf = do { local( @ARGV, $/ ) = $fname; <> };
   return $buf;
}

# arg0 destination path
# arg1 reference to buffer to write (in this case, reference to a scalar)
# - needed as perl-File-Slurp is not in RHEL5
sub write_file
{
    my ($file_name, $buf_ref) = @_;
    open (OUT,  ">$file_name");
    print OUT ${$buf_ref};
    close(OUT);
}    

# set_permissions (path_glob, permissions)
# Return 1 if success, 0 if failure
sub set_permissions
{
    my ($path_glob, $permissions) = @_;
    my (@paths, $errstr, $result, $count);

    $errstr = undef;
    $count = 0;
    $result = 1;

    emit(sprintf("set_permissions(%s, %s)\n",
                 $path_glob,
                 defined($permissions) ? sprintf("%o", $permissions) : ""), "debug");

    return 1 if $dry_run;

    @paths = glob($path_glob);

    if (($count = chmod($permissions, @paths)) != @paths) {
        $errstr = "$!";
        $result = 0;
        emit(sprintf("failed to set permission (%o) on \"%s\" => (%s), %d out of %d failed, \"%s\"\n",
                     $permissions, $path_glob, "@paths", @paths - $count, @paths+0, $errstr), 'error');
    }
    return $result;
}

# Return 1 if success, 0 if failure
sub open_logfile
{
    my ($path, $permissions, $owner, $group) = @_;


    $logfd = FileHandle->new("> $path");

    if (defined($logfd)) {
        $logfile_path = $path;
    } else {
        return 0;
    }

    if (defined($permissions)) {
        return 0 if !set_permissions($logfile_path, $permissions);
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($logfile_path, $owner, $group);
    }

    return 1;
}

# no return value
sub close_logfile
{
    if (defined($logfd)) {
        $logfd->close();
    }

    $logfd = undef;
    return;
}

# return 1 - valid, or
# return 0 - invalid
sub is_path_valid
{
    my ($path) = @_;

    my @pathname = split("/", $path);

    shift @pathname unless $pathname[0];

    my $valid = 0;
    my $split_path;

    foreach $split_path (@pathname) {
        chomp($split_path);

        if (!($split_path !~ /^[-_.a-zA-Z0-9\[\]]+$/)) {
            $valid = 1;
        } else {
            $valid = 0;
            last;
        }
    }

    return $valid;
}

################################################################
# Template Subroutines
###############################################################

# process_file_template
#
# arg0 template_name
# arg1 src_path
# arg2 dst_path
# arg3 substitutions hash ref
# Return 1 if success, 
#        0 if failure
sub process_file_template
{
    my ($template_name, $src_path, $dst_path, $substitutions) = @_;

    my $buf = "";
    my $num_subs = 0;
    my $total_subs = 0;
    my @keys;
    my $key;
    my $value;
    emit("    Template ($template_name) \"${src_path}\" ==> \"${dst_path}\" ...\n");

    # Check for a valid source file
    if (!is_path_valid($src_path)) {
        emit("process_file_template():  invalid source path ${src_path}!\n", "error");
        return 0;
    }

    # Check for a valid destination file
    if (!is_path_valid($dst_path)) {
        emit("process_file_template():  invalid destination path ${dst_path}!\n", "error");
        return 0;
    }

    # Read in contents of source file
    $buf = read_file($src_path);

    # Process each line substituting each [KEY]
    # with its corresponding slot hash value
    @keys = sort(keys %$substitutions);
    foreach $key (@keys) {
        $value = $substitutions->{$key};
        # Perform global substitution on buffer and
        # get count of how many substitutions were actually performed.
        $num_subs = $buf =~ s/\[$key\]/$value/g;
        $total_subs += $num_subs;

        # If any substitutions were performed then log what was done.
        if ($num_subs > 0) {
            # Hide sensitive information by emitting the word "(sensitive)"
            # rather rather than the substituted value.
            if ($key eq $PKI_CERT_DB_PASSWORD_SLOT) {
                emit(sprintf("        %3d substitutions: %s ==> (sensitive)\n", $num_subs, $key));
            } else {
                emit(sprintf("        %3d substitutions: %s ==> \"%s\"\n", $num_subs, $key, $value));
            }
        }
    }

    emit("    $total_subs substitutions were made in '$dst_path'\n");

    # Sanity check, are there any strings left in the buffer which look
    # like a substitution.
    foreach my $match ($buf =~ /\[[A-Z_]+\]/g) {
        emit("WARNING: Possible missed substitution \"$match\" in $src_path");
    }

    #if ($verbose >= 2) {
    #    # For debugging, emit the contents after substitution.
    #     emit(sprintf(">> $dst_path\n%s<< $dst_path\n", $buf));
    #}

    #if (!$dry_run) {
        # Write out these modified contents to the destination file.
        write_file($dst_path, \$buf);
    #}

    return 1;
}

#arg 0 ref to config hash
#return slot hash
sub setup_slot_hash
{
    my ($cfg) = @_;
   
    my $subsystem_type = $cfg->{'pkicreate.subsystem_type'};
    my $host = $cfg->{'service.machineName'};
    my $pki_group = $cfg->{'pkicreate.group'};
    if (($subsystem_type eq $CA) || ($subsystem_type eq $KRA)) {
        $pki_group=$cfg->{'pkicreate.arg11.group'};
    }
    my $pki_user = $cfg->{'pkicreate.user'};
    my $pki_instance_name = $cfg->{'pkicreate.pki_instance_name'};
    my $pki_instance_root = $cfg->{'pkicreate.pki_instance_root'};
    my $pki_security_manager = "-security"; 
    my $install_time = $cfg->{'installDate'};
    
    #ports
    my $agent_secure_port = $cfg->{'pkicreate.agent_secure_port'};
    my $unsecure_port = $cfg->{'pkicreate.unsecure_port'};
    my $secure_port = $cfg->{'pkicreate.secure_port'};
    my $non_clientauth_secure_port = $cfg->{'pkicreate.non_clientauth_secure_port'}; 
    my $ee_secure_port = $cfg->{'pkicreate.ee_secure_port'};
    my $ee_secure_client_auth_port = $cfg->{'pkicreate.ee_secure_client_auth_port'};
    my $admin_secure_port = $cfg->{'pkicreate.admin_secure_port'};
    my $tomcat_server_port = $cfg->{'pkicreate.tomcat_server_port'};

    #paths
    my $pki_instance_path = "$pki_instance_root/$pki_instance_name";
    my $pki_instance_conf_path = "$pki_instance_path/conf";
    if (-l $pki_instance_conf_path) {
        $pki_instance_conf_path = readlink $pki_instance_conf_path;
    }
    my $httpd_conf_instance_file_path = "$pki_instance_conf_path/httpd.conf";
    my $nss_conf_instance_file_path = "$pki_instance_conf_path/nss.conf";
    my $pki_subsystem_path = "/usr/share/pki/$subsystem_type";
    my $pki_cfg_instance_file_path = "$pki_instance_conf_path/CS.cfg";
    my $server_xml_instance_file_path = "$pki_instance_conf_path/server.xml";
    my $webapps_base_subsystem_dir = "webapps";

    #constants
    my $lib_prefix = "lib";
    my $obj_ext    = ".so";
    my $path_sep   = ":";
    my $tmp_dir    = "/tmp";
    my $pki_flavor = "pki";

    #hardware dependent
    my $default_security_libraries = "";
    my $default_system_libraries = "";
    my $default_system_user_libraries = "";

    my $default_hardware_platform = `pkiarch`;
    $default_hardware_platform =~ s/\s+$//g;

    if ($default_hardware_platform eq "i386") {
        $default_system_libraries     = "/lib";
        $default_system_user_libraries = "/usr/lib";
        $default_security_libraries = "/usr/lib/dirsec";
    } elsif( $default_hardware_platform eq "x86_64" ) {
        $default_system_libraries     = "/lib64";
        $default_system_user_libraries = "/usr/lib64";
        $default_security_libraries = "/usr/lib64/dirsec";
    }

    my $use_port_separation = 0;
    if (($subsystem_type ne $RA) &&
        ($subsystem_type ne $TPS) &&
        ($agent_secure_port >= 0)) { 
        $use_port_separation = 1;
    }

    my $buf = read_file("/usr/share/applications/${pki_instance_name}-config.desktop");
    $buf =~ m/pin=(.*)/ ;
    my $random = $1;

    $buf = read_file("$pki_instance_path/$pki_instance_name");
    if ($buf =~ m/TOMCAT_SECURITY_MANAGER="(.*)"/) {
        $pki_security_manager = $1;
    }

    ####################################################
    # Construct slot_hash()
    # Code below taken from pkicreate
    ####################################################

    my %slot_hash = ();

    emit("Processing PKI templates for '$pki_instance_path' ...\n");

    if( $subsystem_type eq $RA || $subsystem_type eq $TPS ) {
        # Setup templates (RA, TPS)
        $slot_hash{$GROUPID}               = $pki_group;
        $slot_hash{$HTTPD_CONF}            = $httpd_conf_instance_file_path;
        $slot_hash{$INSTANCE_ID}           = $pki_instance_name;
        $slot_hash{$INSTANCE_ROOT}         = $pki_instance_root;
        $slot_hash{$LIB_PREFIX}            = $lib_prefix;
        $slot_hash{$NSS_CONF}              = $nss_conf_instance_file_path;
        $slot_hash{$OBJ_EXT}               = $obj_ext;
        $slot_hash{$PORT}                  = $unsecure_port;
        $slot_hash{$PROCESS_ID}            = $$;  #unused in any case
        $slot_hash{$SECURE_PORT}           = $secure_port;
        $slot_hash{$NON_CLIENTAUTH_SECURE_PORT} = $non_clientauth_secure_port;
        $slot_hash{$SECURITY_LIBRARIES}    = $default_security_libraries;
        $slot_hash{$SERVER_NAME}           = $host;
        $slot_hash{$SERVER_ROOT}           = $pki_instance_path;
        $slot_hash{$SUBSYSTEM_TYPE}        = $subsystem_type;
        $slot_hash{$SYSTEM_LIBRARIES}      = $default_system_libraries;
        $slot_hash{$SYSTEM_USER_LIBRARIES} = $default_system_user_libraries;
        $slot_hash{$TMP_DIR}               = $tmp_dir;
        $slot_hash{$TPS_DIR}               = $pki_subsystem_path;
        $slot_hash{$USERID}                = $pki_user;
        $slot_hash{$PKI_FLAVOR_SLOT}       = $pki_flavor;
        $slot_hash{$PKI_RANDOM_NUMBER_SLOT}    = $random;
        $slot_hash{$FORTITUDE_APACHE}  = "Apache2";
        $slot_hash{$FORTITUDE_DIR}     = "/usr";
        $slot_hash{$FORTITUDE_LIB_DIR} = "/etc/httpd";
        $slot_hash{$FORTITUDE_MODULE}  = "/etc/httpd/modules";
        $slot_hash{$FORTITUDE_AUTH_MODULES} =
"
LoadModule auth_basic_module /etc/httpd/modules/mod_auth_basic.so
LoadModule authn_file_module /etc/httpd/modules/mod_authn_file.so
LoadModule authz_user_module /etc/httpd/modules/mod_authz_user.so
LoadModule authz_groupfile_module /etc/httpd/modules/mod_authz_groupfile.so
LoadModule authz_host_module /etc/httpd/modules/mod_authz_host.so
";
        $slot_hash{$FORTITUDE_NSS_MODULES} =
"
LoadModule nss_module  /etc/httpd/modules/libmodnss.so
";
    } else {
        # Setup templates (CA, KRA, OCSP, TKS)
        $slot_hash{$INSTALL_TIME}              = $install_time;
        # $slot_hash{$PKI_CERT_DB_PASSWORD_SLOT} = $db_password; (not used)
        $slot_hash{$PKI_CFG_PATH_NAME_SLOT}    = $pki_cfg_instance_file_path;
        $slot_hash{$PKI_GROUP_SLOT}            = $pki_group;
        $slot_hash{$PKI_INSTANCE_ID_SLOT}      = $pki_instance_name;
        $slot_hash{$PKI_INSTANCE_PATH_SLOT}    = $pki_instance_path;
        $slot_hash{$PKI_INSTANCE_ROOT_SLOT}    = $pki_instance_root;
        $slot_hash{$PKI_MACHINE_NAME_SLOT}     = $host;
        $slot_hash{$PKI_RANDOM_NUMBER_SLOT}    = $random;
        $slot_hash{$PKI_SERVER_XML_CONF}       = $server_xml_instance_file_path;
        $slot_hash{$PKI_SUBSYSTEM_TYPE_SLOT}   = $subsystem_type;
        $slot_hash{$PKI_UNSECURE_PORT_SLOT}    = $unsecure_port;
        # Define "Port Separation" (default) versus "Shared Ports" (legacy)
        if( $use_port_separation)
        {
            # Establish "Port Separation" Connector Names
            $slot_hash{$PKI_UNSECURE_PORT_CONNECTOR_NAME_SLOT}     = $PKI_UNSECURE_PORT_NAME;
            $slot_hash{$PKI_SECURE_PORT_CONNECTOR_NAME_SLOT}       = $PKI_AGENT_SECURE_PORT_NAME;
            $slot_hash{$PKI_ADMIN_SECURE_PORT_CONNECTOR_NAME_SLOT} = $PKI_ADMIN_SECURE_PORT_NAME;
            $slot_hash{$PKI_EE_SECURE_PORT_CONNECTOR_NAME_SLOT}    = $PKI_EE_SECURE_PORT_NAME;
            $slot_hash{$PKI_EE_SECURE_CLIENT_AUTH_PORT_CONNECTOR_NAME_SLOT}    = $PKI_EE_SECURE_CLIENT_AUTH_PORT_NAME;

            # Establish "Port Separation" Connector Ports
            $slot_hash{$PKI_SECURE_PORT_SLOT}       = $agent_secure_port;
            $slot_hash{$PKI_AGENT_SECURE_PORT_SLOT} = $agent_secure_port;
            $slot_hash{$PKI_EE_SECURE_PORT_SLOT}    = $ee_secure_port;
            $slot_hash{$PKI_EE_SECURE_CLIENT_AUTH_PORT_SLOT}    = $ee_secure_client_auth_port;
            $slot_hash{$PKI_ADMIN_SECURE_PORT_SLOT} = $admin_secure_port;

            # Comment "Port Separation" appropriately
            $slot_hash{$PKI_UNSECURE_PORT_COMMENT_SERVER_SLOT}     = $PKI_UNSECURE_SEPARATE_PORTS_COMMENT;
            $slot_hash{$PKI_SECURE_PORT_COMMENT_SERVER_SLOT}       = $PKI_AGENT_SECURE_SEPARATE_PORTS_COMMENT;
            $slot_hash{$PKI_ADMIN_SECURE_PORT_COMMENT_SERVER_SLOT} = $PKI_ADMIN_SECURE_SEPARATE_PORTS_COMMENT;
            $slot_hash{$PKI_EE_SECURE_PORT_COMMENT_SERVER_SLOT}    = $PKI_EE_SECURE_SEPARATE_PORTS_COMMENT;
            $slot_hash{$PKI_EE_SECURE_CLIENT_AUTH_PORT_COMMENT_SERVER_SLOT}    = $PKI_EE_SECURE_CLIENT_AUTH_SEPARATE_PORTS_COMMENT;

            # Set appropriate "clientAuth" parameter for "Port Separation"
            $slot_hash{$PKI_AGENT_CLIENTAUTH_SLOT} = "true";

            # Do NOT comment out the "Admin/EE" Ports
            $slot_hash{$PKI_OPEN_SEPARATE_PORTS_COMMENT_SERVER_SLOT}  = "";
            $slot_hash{$PKI_CLOSE_SEPARATE_PORTS_COMMENT_SERVER_SLOT} = "";
            # Do NOT comment out the "Admin/Agent/EE" Filters
            # used by Port Separation
            $slot_hash{$PKI_OPEN_SEPARATE_PORTS_COMMENT_WEB_SLOT}  = "";
            $slot_hash{$PKI_CLOSE_SEPARATE_PORTS_COMMENT_WEB_SLOT} = "";
        } else {
            # Establish "Shared Ports" Connector Names
            $slot_hash{$PKI_UNSECURE_PORT_CONNECTOR_NAME_SLOT}     = $PKI_UNSECURE_PORT_NAME;
            $slot_hash{$PKI_SECURE_PORT_CONNECTOR_NAME_SLOT}       = $PKI_SECURE_PORT_NAME;
            $slot_hash{$PKI_ADMIN_SECURE_PORT_CONNECTOR_NAME_SLOT} = $PKI_UNUSED_SECURE_PORT_NAME;
            $slot_hash{$PKI_EE_SECURE_PORT_CONNECTOR_NAME_SLOT}    = $PKI_UNUSED_SECURE_PORT_NAME;
            $slot_hash{$PKI_EE_SECURE_CLIENT_AUTH_PORT_CONNECTOR_NAME_SLOT}    = $PKI_UNUSED_SECURE_PORT_NAME;

            # Establish "Shared Ports" Connector Ports
            $slot_hash{$PKI_SECURE_PORT_SLOT}       = $secure_port;
            $slot_hash{$PKI_AGENT_SECURE_PORT_SLOT} = $secure_port;
            $slot_hash{$PKI_EE_SECURE_PORT_SLOT}    = $secure_port;
            $slot_hash{$PKI_EE_SECURE_CLIENT_AUTH_PORT_SLOT}    = $secure_port;
            $slot_hash{$PKI_ADMIN_SECURE_PORT_SLOT} = $secure_port;

            # Comment "Shared Ports" appropriately
            $slot_hash{$PKI_UNSECURE_PORT_COMMENT_SERVER_SLOT}     = $PKI_UNSECURE_SHARED_PORTS_COMMENT;
            $slot_hash{$PKI_SECURE_PORT_COMMENT_SERVER_SLOT}       = $PKI_SECURE_SHARED_PORTS_COMMENT;
            $slot_hash{$PKI_ADMIN_SECURE_PORT_COMMENT_SERVER_SLOT} = "";
            $slot_hash{$PKI_EE_SECURE_PORT_COMMENT_SERVER_SLOT}    = "";
            $slot_hash{$PKI_EE_SECURE_CLIENT_AUTH_PORT_COMMENT_SERVER_SLOT}    = "";

            # Set appropriate "clientAuth" parameter for "Shared Ports"
            $slot_hash{$PKI_AGENT_CLIENTAUTH_SLOT} = "agent";

            # Comment out the "Admin/EE" Ports
            $slot_hash{$PKI_OPEN_SEPARATE_PORTS_COMMENT_SERVER_SLOT}  = $PKI_OPEN_COMMENT;
            $slot_hash{$PKI_CLOSE_SEPARATE_PORTS_COMMENT_SERVER_SLOT} = $PKI_CLOSE_COMMENT;;

            # Comment out the "Admin/Agent/EE" Filters
            $slot_hash{$PKI_OPEN_SEPARATE_PORTS_COMMENT_WEB_SLOT}  = $PKI_OPEN_COMMENT;
            $slot_hash{$PKI_CLOSE_SEPARATE_PORTS_COMMENT_WEB_SLOT} = $PKI_CLOSE_COMMENT;
        }

        $slot_hash{$PKI_WEBAPPS_NAME}          = $webapps_base_subsystem_dir;
        $slot_hash{$PKI_USER_SLOT}             = $pki_user;
        $slot_hash{$TOMCAT_SERVER_PORT_SLOT}   = $tomcat_server_port;
        $slot_hash{$PKI_FLAVOR_SLOT}           = $pki_flavor;
        $slot_hash{$PKI_SECURITY_MANAGER_SLOT} = $pki_security_manager;
    }

    return %slot_hash;
}

# arg0 src directory
# arg1 dest directory
# arg2 config hash ref
# return 1 - success or
# return 0 - failure
sub create_subs_directory
{
    my ($src_dir, $dest_dir, $cfg) = @_;

    if ((scalar keys %subs_hash)== 0 ) {
        %subs_hash = setup_slot_hash($cfg);
    }
  
    mkpath($dest_dir);
    # iterate through the directory
    find({wanted => sub { process_dir_template($src_dir, $dest_dir, \%subs_hash); },
          follow => 1, follow_skip => 2}, $src_dir); 

    # special case for tps/ra
    # this substititution is done during configuration
    my $httpd_conf = "$dest_dir/conf/httpd.conf";
    if ( -e $httpd_conf ){
        my $buf = read_file($httpd_conf);
        $buf =~ s/#\[ErrorDocument_404\]/ErrorDocument 404 \/404.html/;
        $buf =~ s/#\[ErrorDocument_500\]/ErrorDocument 500 \/500.html/;
        write_file($httpd_conf, \$buf);
    }

    return 1; 
}

# arg0 src dir
# arg1 dest_dir
# arg2 substitutions hash ref
# no return value - to be used in File::Find find call 
sub process_dir_template
{
    my ($src_dir, $dest_dir, $subs_ref) = @_;
    my $fname = $File::Find::name;
    my $destname = $fname;
    

    if ($fname eq ".") {
        return;
    }

    $src_dir =~ s/\/+$//;
    $destname =~ s/^$src_dir/$dest_dir/;

    if ( -d $fname ) {
        mkpath($destname);
    } else {
        process_file_template($fname, $fname, $destname, $subs_ref);
    }
}

# arg0 sums file name
# arg1 directory root
# return 1 on success or
#        0 on failure
sub create_sums_file
{
    my ($fname, $dirname) = @_;
    system("cd $dirname; find -L . -type f |xargs md5sum >> $fname");
    return 1;
}


# arg0 old file
# arg1 new file
# arg2 sums files? (1 or 0)
# arg3 changed files hashref
# return 1 - success, or
# return 0 - failure
sub find_changes
{
    my ($old_file, $new_file, $sums, $changed_ref) = @_;

    #read old shared file and add entries to the changed hash
    if (! open(OLD, $old_file)) {
        emit("can not open old shared file $old_file", "error");
        return 0;
    }

    while (my $line = <OLD>) {
        my ($name, $val);
        if (!$sums) {
            if ($line =~ m/^#/) { next; }
            ($name, $val) = split($config_separator, $line, 2);
            chomp($val);
        } else {
            ($val, $name) = split($sums_separator, $line);
            chomp($name);
            $name =~ s/^\.\///;
        }
        $changed_ref->{$name} = { old_val => $val };
    }
    close (OLD);

    if (!open(NEW, $new_file)) {
        emit("cannot open new shared file $new_file", "error");
        return 0;
    }

    while (my $line = <NEW>) {
        my ($name, $val);
        if (!$sums) {
            if ($line =~ m/^#/)  { next; } 
            ($name, $val) = split($config_separator, $line, 2);
            chomp($val);
        } else {
            ($val, $name) = split($sums_separator, $line);
            chomp($name);
            $name =~ s/^\.\///;
        }
        if (defined $changed_ref->{$name}) {
            if ($changed_ref->{$name}{old_val} eq $val) {
                delete $changed_ref->{$name};
            } else {
                $changed_ref->{$name}{new_val} = $val;
            }
        } else {
            $changed_ref->{$name} = { new_val => $val };
        }
    }
    close (NEW);
    return 1;
}

# arg0 instance file
# arg1 sums? (1 or 0)
# arg2 field 
# arg3 changed files hashref
# return 1 - success, or
# return 0 - failure
sub populate_hash_values
{
    my ($inst_file, $sums, $field, $changed_ref) = @_;

    if (! open(INST, $inst_file)) {
        emit("can not open instance file $inst_file", "error");
        return 0;
    }

    while (my $line = <INST>) {
        my ($name, $val);
        if (!$sums) {
            if ($line =~ m/^#/) { next; }
            ($name, $val) = split($config_separator, $line, 2);
            chomp($val);
        } else {
            ($val, $name) = split($sums_separator, $line);
            chomp($name);
            $name =~ s/^\.\///;
        }
        if (defined $changed_ref->{$name}) {
            $changed_ref->{$name}{$field} = $val;
        }
    }
    close (INST);
    return 1;
}

# arg0 changes hashref
# arg1 actions hash
# arg2 sums? (1 or 0)
# arg3 ignore list ref 
# arg4 redirect hash ref
# return 1 - success or
# return 0 - failure
sub check_for_customizations
{
    my ($changed_ref, $actions_ref, $sums, $ignore_ref, $redirect_ref) = @_;
    my @to_be_added;
    my @to_be_deleted;
    my @to_be_replaced;
    my @to_be_checked_add;
    my @to_be_checked_delete;
    my @to_be_checked_replace;
    my @to_be_checked_replace_add;
    my @no_action_required;

    while ( my ($fname, $fhash) = each(%$changed_ref)) {
        emit($fname);

        if (!$sums) {
            if ($fname =~ m/^preop\./) {
                next;
            }
        } 
  
        if (grep {$_ eq $fname} @{$ignore_ref}) {
            next;
        }
 
        if (defined $redirect_ref) {
           if (defined $redirect_ref->{$fname}) {
               my $fval = $redirect_ref->{$fname}; 
               if (-f $fval) {
                   my $sum = `md5sum $fval`;
                   $sum =~ s/(.*)$sums_separator(.*)/$1/;
                   chomp($sum);
                   $fhash->{inst_val} = $sum;
                   emit("Getting sum for redirected file $fval for $fname : $fhash->{inst_val}");
               }
           }
        }
             
        if (defined $fhash->{new_val}) {
            if (defined $fhash->{old_val}) {                      # replaced value
                if (defined $fhash->{inst_val}) {                 # instance value exists
                    if ($fhash->{inst_val} eq $fhash->{old_s}) {
                        push @to_be_replaced, $fname;
                    } else {
                        if ($fhash->{inst_val} eq $fhash->{new_s}) {  # value already replaced
                            push @no_action_required, $fname;
                        } else {
                            push @to_be_checked_replace, $fname;
                        }
                    }
                } else {                            # instance value does not exist
                    push @to_be_checked_replace_add, $fname;
                }
            } else {                                # new value
                if (defined $fhash->{inst_val}) {   # instance value already exists
                    if ($fhash->{inst_val} eq $fhash->{new_s}) {
                        push @no_action_required, $fname;
                    } else {
                        push @to_be_checked_add, $fname;
                    }
                } else {
                    push @to_be_added, $fname;
                }
            }
        } else {                                     # value deleted
            if (defined $fhash->{inst_val}) {        # value exists
                if ($fhash->{inst_val} eq $fhash->{old_s}) {
                    push @to_be_deleted, $fname;
                } else {
                    push @to_be_checked_delete, $fname;
                }
            } else {                                 # value already deleted
                push @no_action_required, $fname;
            }
        }
    }
    $actions_ref->{no_action_required}        = \@no_action_required;
    $actions_ref->{to_be_replaced}            = \@to_be_replaced;
    $actions_ref->{to_be_added}               = \@to_be_added;
    $actions_ref->{to_be_deleted}             = \@to_be_deleted;
    $actions_ref->{to_be_checked_delete}      = \@to_be_checked_delete;
    $actions_ref->{to_be_checked_replace}     = \@to_be_checked_replace;
    $actions_ref->{to_be_checked_replace_add} = \@to_be_checked_replace_add;
    $actions_ref->{to_be_checked_add}         = \@to_be_checked_add;

    return 1;
}

# arg0 actions hashref
# arg1 instance path
# arg2 subsystem path
# directories hash ref
# arg3 redirects hash ref
# return 1 - success or
# return 0 - failure
sub perform_file_actions
{
    my ($actions_ref, $instance_path, $subsystem_path, $directories_ref, $redirect_ref) = @_;
    my @to_be_added               = @{$actions_ref->{to_be_added}};
    my @to_be_deleted             = @{$actions_ref->{to_be_deleted}};
    my @to_be_replaced            = @{$actions_ref->{to_be_replaced}};
    my @to_be_checked_add         = @{$actions_ref->{to_be_checked_add}};
    my @to_be_checked_delete      = @{$actions_ref->{to_be_checked_delete}};
    my @to_be_checked_replace     = @{$actions_ref->{to_be_checked_replace}};
    my @to_be_checked_replace_add = @{$actions_ref->{to_be_checked_replace_add}};
    my @no_action_required        = @{$actions_ref->{no_action_required}};
    my @dir_to_be_added           = @{$directories_ref->{to_be_added}};
    my @dir_to_be_deleted         = @{$directories_ref->{to_be_deleted}};

    if (!$dry_run) {
        emit("The following actions are being performed:\n", "info");
    } else {
        emit("If dry_run were not set to true, the following actions would be performed:\n", "info");
    }

    # Added directories
    foreach my $fname (@dir_to_be_added) {
        my $destfile = "${instance_path}/${fname}";
        if (! -e $destfile ) {
            emit("Create directory $destfile", "info");
            if (!$dry_run) {
                mkpath($destfile);
                my $uid   = getpwnam($pki_user);
                my $gid   = getgrnam($pki_group);
                chown $uid, $gid, $destfile;
            }
        }
    }
        
    # Added files
    foreach my $fname (@to_be_added) {
        my $destfile = "${instance_path}/${fname}";
        if ((defined $redirect_ref) && (defined $redirect_ref->{$fname})) {
            $destfile = $redirect_ref->{$fname};
        }
        emit("Copying the new file $destfile from ${subsystem_path}/${fname}",
             "info");
        if (!$dry_run) {
            copy_file("${subsystem_path}/${fname}", $destfile,
                      $default_file_permissions, $pki_user, $pki_group);
        }
    }

    # Replaced files
    foreach my $fname (@to_be_replaced) {
        my $destfile = "${instance_path}/${fname}";
        if ((defined $redirect_ref) && (defined $redirect_ref->{$fname})) { 
            $destfile = $redirect_ref->{$fname};
        }
        emit("Replacing the file $destfile from ${subsystem_path}/${fname}",
             "info");
        if (!$dry_run) {
            remove_file($destfile);
            copy_file("${subsystem_path}/${fname}", $destfile,
                      $default_file_permissions, $pki_user, $pki_group);
        }
    }

    # Deleted files
    foreach my $fname (@to_be_deleted) {
        my $destfile = "${instance_path}/${fname}";
        if ((defined $redirect_ref) && (defined $redirect_ref->{$fname})) { 
            $destfile = $redirect_ref->{$fname};
        }
        emit("Deleting the following file:  $destfile", "info");
        if (!$dry_run) {
            remove_file("$destfile");
        }
    }

    # Check add files
    if (scalar(@to_be_checked_add) > 0) {
        if (!$overwrite) {
            emit("The following files are new files that are supposed to be copied from " .
                 "$subsystem_path to $instance_path  " .
                 "However, different (possibly customized) files currently exist at " .
                 "$instance_path. Please check and address.",
                 "info");
            foreach my $fname (@to_be_checked_add) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files are new files that will be copied from " .
                 "$subsystem_path to $instance_path  " .
                 "However, different (possibly customized) files currently exist at " .
                 "$instance_path.  " .
                 "As the overwrite option is enabled, the existing files will be backed up " .
                 "and overwritten.  Please check and address any issues.",
                 "info");
            foreach my $fname (@to_be_checked_add) {
                my $destfile = "${instance_path}/${fname}";
                if ((defined $redirect_ref) && (defined $redirect_ref->{$fname})) { 
                   $destfile = $redirect_ref->{$fname};
                }
                emit("Backing up and replacing the file $destfile " .
                     "from ${subsystem_path}/${fname}",
                     "info");
                copy_file($destfile, "${destfile}.orig_$$",
                          $default_file_permissions, $pki_user, $pki_group);
                remove_file($destfile);
                copy_file("${subsystem_path}/${fname}", $destfile,
                          $default_file_permissions, $pki_user, $pki_group);
            }
        }
    }

    # Check delete files
    if (scalar(@to_be_checked_delete) > 0) {
        if (!$overwrite) {
            emit("The following files are supposed to be deleted from $instance_path  " .
                 "However, the files that exist at that location appear to have been customized.  " .
                 "Please check and address.", "info");
            foreach my $fname (@to_be_checked_delete) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files are supposed to be deleted from $instance_path  " .
                 "However, the files that exist at that location appear to have been customized. \n" .
                 "As the overwrite option is enabled, the existing files will be backed up " .
                 "and deleted.  Please check and address any issues.",
                 "info");
            foreach my $fname (@to_be_checked_delete) {
                my $destfile = "${instance_path}/${fname}";
                if ((defined $redirect_ref) && (defined $redirect_ref->{$fname})) { 
                   $destfile = $redirect_ref->{$fname};
                }
                emit("Backing up and deleting the file $destfile");
                copy_file($destfile, "${destfile}.orig_$$",
                          $default_file_permissions, $pki_user, $pki_group);
                remove_file($destfile);
            }
        }
    }

    # Check replace files
    if (scalar(@to_be_checked_replace) > 0) {
        if (!$overwrite) {
            emit("The following files in $instance_path are supposed to be replaced " .
                 "by new versions in $subsystem_path  " .
                 "However, the files that exist at that location appear to have been customized.  " .
                 "Please check and address.",
                 "info");
            foreach my $fname (@to_be_checked_replace) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files in $instance_path are supposed to be replaced " .
                 "by new versions in $subsystem_path  " .
                 "However, the files that exist at that location appear to have been customized. \n" .
                 "As the overwrite option is enabled, the existing files will be backed up " .
                 "and replaced.  Please check and address any issues.",
                 "info");
            foreach my $fname (@to_be_checked_replace) {
                my $destfile = "${instance_path}/${fname}";
                if ((defined $redirect_ref) && (defined $redirect_ref->{$fname})) { 
                   $destfile = $redirect_ref->{$fname};
                }
                emit("Backing up and replacing the file $destfile " .
                     "from ${subsystem_path}/${fname}",
                     "info");
                copy_file($destfile, "${destfile}.orig_$$",
                          $default_file_permissions, $pki_user, $pki_group);
                remove_file($destfile);
                copy_file("${subsystem_path}/${fname}", $destfile,
                          $default_file_permissions, $pki_user, $pki_group);
            }
        }
    }

    # Check replace add files
    if (scalar(@to_be_checked_replace_add) > 0) {
        if (!$overwrite) {
            emit("The following files in $instance_path are supposed to be replaced " .
                 "by new versions in $subsystem_path  " .
                 "However, the old files in $instance_path do not exist, and may have ".
                 "been deleted as part of a customization.  " .
                 "Please check and address.", "info");
            foreach my $fname (@to_be_checked_replace_add) {
                emit("    $fname", "info");
            }
        } else {
            emit("The following files in $instance_path are supposed to be replaced " .
                 "by new versions in $subsystem_path  " .
                 "However, the old files in $instance_path do not exist, and may have " .
                 "been deleted as part of a customization. \n" .
                 "As the overwrite option is enabled, the file will be copied over from " .
                 "$subsystem_path notwithstanding.  " .
                 "Please check and address any issues.", "info");
            foreach my $fname (@to_be_checked_replace_add) {
                my $destfile = "${instance_path}/${fname}";
                if ((defined $redirect_ref) && (defined $redirect_ref->{$fname})) { 
                   $destfile = $redirect_ref->{$fname};
                }
                emit("Adding the file $destfile from " .
                     "${subsystem_path}/${fname}", "info");
                copy_file("${subsystem_path}/${fname}", $destfile,
                          $default_file_permissions, $pki_user, $pki_group);
            }
        }
    }

    # Deleted directories
    foreach my $fname (@dir_to_be_deleted) {
        my $destfile = "${instance_path}/${fname}";
        if (-e $destfile) {
            emit("Delete directory $destfile if it is empty.", "info");
            if (!$dry_run) {
                if ((-d $destfile) && (! scalar <$destfile/*>)) { # directory is empty
                    rmtree($destfile, {user => $pki_user, group => $pki_group});
                }
            }
        }
    }

    return 1;
}

# arg0 path to instance cs.cfg
# arg1 config changes hashref
# arg2 actions hashref
# return 1 - success or
# return 0 - failure
sub perform_cs_actions
{
    my ($inst_file, $changes_ref, $actions_ref) = @_;
    my @to_be_added               = @{$actions_ref->{to_be_added}};
    my @to_be_deleted             = @{$actions_ref->{to_be_deleted}};
    my @to_be_replaced            = @{$actions_ref->{to_be_replaced}};
    my @to_be_checked_add         = @{$actions_ref->{to_be_checked_add}};
    my @to_be_checked_delete      = @{$actions_ref->{to_be_checked_delete}};
    my @to_be_checked_replace     = @{$actions_ref->{to_be_checked_replace}};
    my @to_be_checked_replace_add = @{$actions_ref->{to_be_checked_replace_add}};
    my @no_action_required        = @{$actions_ref->{no_action_required}};

    my %inst_vals = ();

    return 0 if !read_cfg($inst_file, \%inst_vals);

    if (!$dry_run) {
        emit("The following actions are being performed on $inst_file:\n", "info");
    } else {
        emit("If dry_run were not set to true, the following actions would be performed on " .
             "$inst_file:\n", "info");
    }

    # Added values
    foreach my $name (@to_be_added) {
        emit("Adding new parameter $name => " . $changes_ref->{$name}{new_s}, "info");
        if (!$dry_run) {
            $inst_vals{$name}=$changes_ref->{$name}{new_s};
        }
    }

    # Replaced values
    foreach my $name (@to_be_replaced) {
        emit("Replacing the parameter $name => " . $changes_ref->{$name}{new_s}, "info");
        if (!$dry_run) {
            $inst_vals{$name}=$changes_ref->{$name}{new_s};
        }
    }

    # Deleted values
    foreach my $name (@to_be_deleted) {
        emit("Deleting the parameter $name => " . $inst_vals{$name}, "info");
        if (!$dry_run) {
            delete $inst_vals{$name};
        }
    }

    # Check add values
    if (scalar(@to_be_checked_add) > 0) {
        if (!$overwrite) {
            emit("The following parameters are supposed to be added to $inst_file  " .
                 "However, this parameter already exists and with a different (possibly customized) " .
                 "value.  Please check and address.",
                 "info");
            foreach my $name (@to_be_checked_add) {
                emit("    $name => " . $changes_ref->{$name}{new_s}, "info");
            }
        } else {
            emit("The following parameters are supposed to be added to $inst_file  " .
                 "However, this parameter already exists and with a different (possibly customized) " .
                 "value.\n As the overwrite option is enabled, the existing parameter will be " .
                 "overwritten.  Please check and address any issues.",
                 "info");

            foreach my $name (@to_be_checked_add) {
                emit("    $name => " . $changes_ref->{$name}{new_s}, "info");
                if (!$dry_run) {
                    $inst_vals{$name}=$changes_ref->{$name}{new_s};
                }
            }
        }
    }

    # Check delete values
    if (scalar(@to_be_checked_delete) > 0) {
        if (!$overwrite) {
            emit("The following parameters are supposed to be deleted from $inst_file  " .
                 "However, this parameter has a value that may have been customized.  " .
                 "Please check and address.",
                 "info");
            foreach my $name (@to_be_checked_delete) {
                emit("    $name  => $inst_vals{$name}", "info");
            }
        } else {
            emit("The following parameters are supposed to be deleted from $inst_file  " .
                 "However, this parameter has a value that may have been customized\n" .
                 "As the overwrite option is enabled, the existing parameter will be " .
                 "deleted notwithstanding.  Please check and address any issues.",
                 "info");
            foreach my $name (@to_be_checked_delete) {
                emit("    $name  => $inst_vals{$name}", "info");
                delete $inst_vals{$name};
            }
        }
    }

    # Check replace values
    if (scalar(@to_be_checked_replace) > 0) {
        if (!$overwrite) {
            emit("The following parameters in $inst_file are supposed to be replaced by new values.  " .
                 "However, these parameters have values that may have been customized.  " .
                 "Please check and address.",
                 "info");
            foreach my $name (@to_be_checked_replace) {
                emit("    $name => " . $changes_ref->{$name}{new_s}, "info");
            }
        } else {
            emit("The following parameters in $inst_file are supposed to be replaced by new values.  " .
                 "However, these parameters have values that may have been customized\n" .
                 "As the overwrite option is enabled, the existing parameters will be " .
                 "replaced notwithstanding.  Please check and address any issues.",
                 "info");
            foreach my $name (@to_be_checked_replace) {
                emit("    $name => " . $changes_ref->{$name}{new_s}, "info");
                if (!$dry_run) {
                    $inst_vals{$name}=$changes_ref->{$name}{new_s};
                }
            }
        }
    }

    # Check replace add files
    if (scalar(@to_be_checked_replace_add) > 0) {
        if (!$overwrite) {
            emit("The following parameters in $inst_file are supposed to be replaced by new values.  " .
                 "However, these parameters are not present in $inst_file and may have been " .
                 "removed as a customization.  Please check and address.",
                 "info");
            foreach my $name (@to_be_checked_replace_add) {
                emit("    $name => " . $changes_ref->{$name}{new_s}, "info");
            }
        } else {
            emit("The following parameters in $inst_file are supposed to be replaced by new values.  " .
                 "However, these parameters are not present in $inst_file and may have been " .
                 "removed as a customization\n" .
                 "As the overwrite option is enabled, the parameter will be replaced " .
                 "notwithstanding.  Please check and address any issues.",
                 "info");
            foreach my $name (@to_be_checked_replace_add) {
                emit("    $name => " . $changes_ref->{$name}{new_s}, "info");
                if (!$dry_run) {
                    $inst_vals{$name}=$changes_ref->{$name}{new_s};
                }
            }
        }
    }

    if (!$dry_run) {
        my $backup_fname = "$inst_file.backup_$$";
        emit("Backing up $inst_file to $backup_fname");
        copy_file($inst_file, $backup_fname, $default_file_permissions, $pki_user, $pki_group);

        if (! open(INST, ">", $inst_file)) {
            emit("can not open $inst_file for writing", "error");
            return 0;
        }

        emit("Writing new $inst_file");
        foreach my $name (sort keys %inst_vals) {
            print INST "$name=$inst_vals{$name}\n";
        }
        close (INST);
    }
    return 1;
}

# arg0 path to instance cs.cfg
# arg1 hash ref for cs.cfg
# return 1 - success or
# return 0 - failure
sub read_cfg
{
    my ($cfg_file, $cfg_ref) = @_;

    if (! open(CFG, $cfg_file)) {
        emit("cannot open instance file $cfg_file", "error");
        return 0;
    }

    while (my $line = <CFG>) {
        my ($name, $val) = split($config_separator, $line, 2);
        chomp($val);
        $cfg_ref->{$name} = $val;
    }
    close (CFG);
    return 1;
}

# arg0 list1 (as a comma delimited string)
# arg1 list2 (as a comman delimited string)
# return 1 - if lists equal
# return 0 - otherwise
sub list_values_equal
{
    my ($list_value1, $list_value2) = @_;
    my @list1 = sort(split(",", $list_value1));
    my @list2 = sort(split(",", $list_value2));
    if ($#list1 != $#list2) {
        return 0;
    }
    for (my $i=0; $i < $#list1; $i++) {
        if ($list1[$i] ne $list2[$i]) {
            return 0;
        }
    } 
    return 1; 
}

# arg0 old directory path
# arg1 new directory path
# arg2 changes hash ref 
# return 1 - for success
sub find_directory_changes
{
    my ($old_dir, $new_dir, $changes_ref) = @_;
    my @to_be_added;
    my @to_be_deleted;

    find({wanted => sub { 
                            if (-d $_) {
                                my $dir = $File::Find::name;
                                if ($dir eq $old_dir) { return; }
                                $dir =~ s/$old_dir\///;
                                $changes_ref->{$dir}{old_val}=1;
                            } 
                        }
         }, 
         $old_dir);
    find({wanted => sub { 
                            if (-d $_) {
                                my $dir = $File::Find::name;
                                if ($dir eq $new_dir) { return; }
                                $dir =~ s/$new_dir\///;
                                if (defined $changes_ref->{$dir}) {
                                    delete $changes_ref->{$dir};
                                } else {
                                   $changes_ref->{$dir}{new_val}=1;
                                } 
                             }
                         }
          }, 
          $new_dir);

    while( my ($k, $v) = each %$changes_ref ) {
        if (defined $v->{old_val}) { 
            push @to_be_deleted, $k;
        }
        if (defined $v->{new_val}) { 
            push @to_be_added, $k;
        }
    }
    $changes_ref->{to_be_added}   = \@to_be_added;
    $changes_ref->{to_be_deleted} = \@to_be_deleted;

    return 1;
}

1;
