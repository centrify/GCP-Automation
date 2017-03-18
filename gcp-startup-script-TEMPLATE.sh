#!/bin/bash

################################################################################
#
# Copyright (C) 2017 Centrify Corporation. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at
#      http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed 
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR 
# CONDITIONS OF ANY KIND, either express or implied. See the License for the 
# specific language governing permissions and limitations under the License.
#
#
# Sample script for orchestration on GCP
#
# This sample script is to demonstrate how GCP instances can be orchestrated to
# join Centrify Privilege Service through the Centrify agent.
#
################################################################################




# >>> DATA >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


#
# User configurations
#

# Specify the customer tenant URL to enroll in cenroll CLI
TENANT_URL="tenant-name.my.centrify.com"

# Specify the enrollment code to use in cenroll CLI
ENROLLMENT_CODE=A0000000-9000-4000-8000-C00000000000

# Specify the roles to grant "AgentAuth" right in cenroll CLI
AGENT_AUTH_ROLES="UnixUsers"

# Specify the features to enable in cenroll CLI
FEATURES="aapm,agentauth"

# Specify the type of network address. Possible values:
# "PublicIP" (default), "PrivateIP" or "HostName"
NETWORK_ADDR_TYPE="PrivateIP"

# Specify the prefix of the login name to use for this computer in the Centrify
# identity platform. The format is <prefix>-<GCP instance ID>.
COMPUTER_NAME_PREFIX="gcp"

# Temp directory
TEMP_DIR="/tmp"

# Centrify Connector
# Computers that need to enroll but do not have internet connectivity will require
# being configured to communicate via the Connector in order to enroll in the Privilege Service
CONNECTOR_URL="https://yourdomaincontroller:8080"
CONNECTOR="domaincontrollers-shortname-here"

#
# Parameters for AD Join
AD_CONTAINER="ou=GCP,dc=company,dc=com"
ZONE="gcp-project-name"
# Keytab file url in Google Storage Bucket
KEYTAB_FILE="gs://bucketname/computerjoin.keytab"
AD_DOMAIN="gcp.company.com"

#
# Parameters for Centrify Repo
REPO_URL="https://Your-Repo-Access-Key-Here@repo.centrify.com/rpm-redhat/"


#
# Other configurations
#

# Directory for orchestration
ORCH_DIR="$TEMP_DIR/orchestration"

# Log file location
LOG_FILE="$ORCH_DIR/gcp_startup_script.log"

# URI (Uniform Resource Identifer) provided by GCP to query instance metadata
GCP_METADATA_URI="http://metadata.google.internal/computeMetadata/v1/instance"

# Specify how to run curl
CURL="/usr/bin/curl --silent --show-error -H Metadata-Flavor:Google"

# URL to get CentrifyCC install package via curl
CENTRIFYCC_DOWNLOAD_URL="http://downloads.centrify.com.s3.amazonaws.com/products/cloud-service/CliDownload/Centrify"
CENTRIFYCC_PACKAGE_NAME="CentrifyCC-rhel6.x86_64.rpm"


#
# Global variables
#

# Return code
RC=

# ID of the AWS instance
INSTANCE_ID=

# Network address of the AWS instance (according to NETWORK_ADDR_TYPE)
NETWORK_ADDR=

# Specify how to restart SSH daemon
SSHD_RESTART=


# >>> FUNCTIONS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

function check_input()
{
    if [ -z "$TENANT_URL" ] || \
       [ -z "$ENROLLMENT_CODE" ] || \
       [ -z "$AGENT_AUTH_ROLES" ] || \
       [ -z "$FEATURES" ] || \
       [ -z "$NETWORK_ADDR_TYPE" ] || \
       [ -z "$COMPUTER_NAME_PREFIX" ] || \
       [ -z "$CENTRIFYCC_DOWNLOAD_URL" ]
    then
        echo "Please provide user configurations" >> $LOG_FILE
        return 1
    fi
}

function get_instance_data()
{
    echo >> $LOG_FILE
    echo $(date) "Getting GCP instance data..." >> $LOG_FILE
    echo >> $LOG_FILE

    #
    # Instance ID
    #

    INSTANCE_ID=$($CURL "$GCP_METADATA_URI/hostname" 2>> $LOG_FILE)
    
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to get instance ID: $RC" >> $LOG_FILE
        return $RC
    fi

    echo "Instance ID: $INSTANCE_ID" >> $LOG_FILE

    #
    # Network address
    #

    # PublicIP is the default
    if [ "$NETWORK_ADDR_TYPE" = "PrivateIP" ]; then
        NETWORK_ADDR=$($CURL "$GCP_METADATA_URI/network-interfaces/0/ip" 2>> $LOG_FILE)
    elif [ "$NETWORK_ADDR_TYPE" = "HostName" ]; then
        NETWORK_ADDR=$(/bin/hostname --fqdn)
    else
        NETWORK_ADDR=$($CURL "$GCP_METADATA_URI/network-interfaces/0/access-configs/0/external-ip" 2>> $LOG_FILE)
    fi

    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to get network address: $RC" >> $LOG_FILE
        return $RC
    fi

    echo "Network address: $NETWORK_ADDR (type: $NETWORK_ADDR_TYPE)" >> $LOG_FILE
}

function set_hostname()
{
    echo >> $LOG_FILE
    echo $(date) "Setting hostname..." >> $LOG_FILE
    echo >> $LOG_FILE

    COMPUTER_NAME="$COMPUTER_NAME_PREFIX-$INSTANCE_ID"
	/bin/hostname "$COMPUTER_NAME" >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to set hostname: $RC" >> $LOG_FILE
        return $RC
    fi
}

function get_platform()
{
    echo >> $LOG_FILE
    echo $(date) "Getting platform..." >> $LOG_FILE
    echo >> $LOG_FILE

    /bin/cat /etc/system-release >> $LOG_FILE 2>&1 
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to get platform: $RC" >> $LOG_FILE
        return $RC
    fi

    if [ -x /usr/bin/systemctl ]; then
        echo "Init system: systemd" >> $LOG_FILE
        SSHD_RESTART="systemctl restart sshd.service"
    else
        echo "Init system: System V" >> $LOG_FILE
        SSHD_RESTART="/etc/init.d/sshd restart"
    fi
}

function yum_install()
{
    PACKAGE="$1"

    /usr/bin/yum --quiet list $PACKAGE >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to list $PACKAGE: $RC" >> $LOG_FILE
        return $RC
    fi

    /usr/bin/yum --quiet --assumeyes install $PACKAGE >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to install $PACKAGE: $RC" >> $LOG_FILE
        return $RC
    fi
}

function install_prerequisites()
{
    echo >> $LOG_FILE
    echo $(date) "Installing pre-requisites..." >> $LOG_FILE
    echo >> $LOG_FILE
    
    yum_install "selinux-policy-targeted"
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

    yum_install "perl"
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi
}

function install_gcp_logging_agent()
{
    echo >> $LOG_FILE
    echo $(date) "Installing GCP Logging Agent..." >> $LOG_FILE
    echo >> $LOG_FILE
    
	# Install GCP Logging Agent (https://cloud.google.com/logging/docs/agent/installation)
    curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh
    bash install-logging-agent.sh
    # TODO fix the agent to log /var/log/secure
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi
}

function install_agent()
{
    # Clean up previously downloaded package if needed
    if [ -f $ORCH_DIR/$CENTRIFYCC_PACKAGE_NAME ]; then
        echo >> $LOG_FILE
        echo $(date) "Deleting previously downloaded package..." >> $LOG_FILE
        echo >> $LOG_FILE

        rm $ORCH_DIR/$CENTRIFYCC_PACKAGE_NAME >> $LOG_FILE 2>&1
        RC=$?
        if [ "$RC" != "0" ]; then
            echo "Failed to delete previously downloaded package: $RC" >> $LOG_FILE
            return $RC
        fi
    fi

    echo >> $LOG_FILE
    echo $(date) "Downloading package..." >> $LOG_FILE
    echo >> $LOG_FILE

    echo "URL: [$CENTRIFYCC_DOWNLOAD_URL/$CENTRIFYCC_PACKAGE_NAME]" >> $LOG_FILE
    $CURL $CENTRIFYCC_DOWNLOAD_URL/$CENTRIFYCC_PACKAGE_NAME --output $ORCH_DIR/$CENTRIFYCC_PACKAGE_NAME >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to download package: $RC" >> $LOG_FILE
        return $RC
    fi

    echo >> $LOG_FILE
    echo $(date) "Listing package information..." >> $LOG_FILE
    echo >> $LOG_FILE

    /bin/rpm --query --info --package $ORCH_DIR/$CENTRIFYCC_PACKAGE_NAME >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to list information from package: $RC" >> $LOG_FILE
        return $RC
    fi

    echo >> $LOG_FILE
    echo $(date) "Installing package..." >> $LOG_FILE
    echo >> $LOG_FILE

    /bin/rpm --install --hash --quiet $ORCH_DIR/$CENTRIFYCC_PACKAGE_NAME >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to install package: $RC" >> $LOG_FILE
        return $RC
    fi

    echo >> $LOG_FILE
    echo $(date) "Getting installed version..." >> $LOG_FILE
    echo >> $LOG_FILE

    /usr/bin/cinfo --version >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to get installed version: $RC" >> $LOG_FILE
        return $RC
    fi
}

function configure_agent()
{
    echo >> $LOG_FILE
    echo $(date) "Configuring Centrify agent settings..." >> $LOG_FILE
    echo >> $LOG_FILE

    # TODO: set post-enroll hook
}

function enroll()
{
    COMPUTER_NAME="$COMPUTER_NAME_PREFIX-$INSTANCE_ID"

    echo >> $LOG_FILE
    echo $(date) "Enrolling in Centrify identity platform..." >> $LOG_FILE
    echo >> $LOG_FILE

    # Create a centrify proxy account for management
    useradd --shell /bin/bash --create-home centrify
    PASSWORD=`openssl rand -base64 8`
	# echo "Proxy account password: $PASSWORD" >> $LOG_FILE
	echo "centrify:$PASSWORD" | chpasswd >> $LOG_FILE 2>&1

    /usr/sbin/cenroll \
        --tenant "$TENANT_URL" \
        --code "$ENROLLMENT_CODE" \
        --features "$FEATURES" \
        --agentauth "$AGENT_AUTH_ROLES" \
        --name "$COMPUTER_NAME" \
        --address "$NETWORK_ADDR" \
        --resource-setting ProxyUser:centrify \
        --resource-setting ProxyUserPassword:$PASSWORD \
        --resource-setting ProxyUserIsManaged:true \
        --resource-setting \"Connectors:$CONNECTOR\" \
        >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to enroll in Centrify identity platform: $RC" >> $LOG_FILE
        return $RC
    fi

    # Log status after enrolled
    /usr/bin/cinfo >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to get status after enrolled: $RC" >> $LOG_FILE
        return $RC
    fi
}

function configure_sshd()
{
    echo >> $LOG_FILE
    echo $(date) "Configuring sshd..." >> $LOG_FILE
    echo >> $LOG_FILE

    # Comment out the line to enable password authentication
    SSH_PASSWORD_AUTH="PasswordAuthentication no"
    /bin/sed --in-place "s/^$SSH_PASSWORD_AUTH/#$SSH_PASSWORD_AUTH/g" /etc/ssh/sshd_config >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to edit sshd config: $RC" >> $LOG_FILE
        return $RC
    fi

    $SSHD_RESTART >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to restart sshd: $RC" >> $LOG_FILE
        return $RC
    fi
}

function vault_root()
{
	echo >> $LOG_FILE
    echo $(date) "Vaulting root account..." >> $LOG_FILE
    echo >> $LOG_FILE
        
    # Set the root password and vault it
    PASSWORD=`openssl rand -base64 8`
    # echo "root password: $PASSWORD" >> $LOG_FILE
	echo "root:$PASSWORD" | chpasswd >> $LOG_FILE 2>&1
	echo "$PASSWORD" | csetaccount --verbose --stdin --managed true --useproxy true root >> $LOG_FILE 2>&1
}

function add_ad_dns()
{
	echo >> $LOG_FILE
    echo $(date) "Adding AD Domain Controller as DNS Server..." >> $LOG_FILE
    echo >> $LOG_FILE
        
    # Adding AD Domain Controller as DNS Server
    # 
    # UPDATE FOR YOUR DOMAIN CONTROLLER HERE
    # 
	cat >> /etc/dhclient.conf << EOF
supersede domain-name "gcp.company.com" ; 
prepend domain-name-servers 10.1.1.1 ;
EOF

	# restart the network
	/etc/init.d/network restart
	sleep 10
	
}

function install_centrifydc()
{
	echo >> $LOG_FILE
    echo $(date) "Installing CentrifyDC..." >> $LOG_FILE
    echo >> $LOG_FILE

	# Add Centrify yum repo to the repos.d directory
	#
	# UPDATE FOR YOUR REPO KEY HERE 
	# 
	cat > /etc/yum.repos.d/centrify.repo << EOF
[centrify]
name=centrify
baseurl=https://Your-Repo-Access-Key-Here@repo.centrify.com/rpm-redhat/
enabled=1
repo_gpgcheck=1
gpgcheck=1
gpgkey=https://edge.centrify.com/products/RPM-GPG-KEY-centrify
EOF
	
	chmod 644 /etc/yum.repos.d/centrify.repo
	
	# Install Centrify DirectControl
	yum install -y CentrifyDC
}

function get_keytab_file()
{
	echo >> $LOG_FILE
    echo $(date) "Getting keytab file..." >> $LOG_FILE
    echo >> $LOG_FILE

    gsutil cp $KEYTAB_FILE $ORCH_DIR/login.keytab >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to download package: $RC" >> $LOG_FILE
        return $RC
    fi

    chmod 0600 $ORCH_DIR/login.keytab
}

function get_user_and_domain()
{
	echo >> $LOG_FILE
    echo $(date) "Extracting user and domain..." >> $LOG_FILE
    echo >> $LOG_FILE

    JOIN_USER=`/usr/share/centrifydc/kerberos/bin/klist -k $ORCH_DIR/login.keytab | grep @ | awk '{print $2}' | sed -n '1p'`
    DOMAIN_NAME=`/usr/share/centrifydc/kerberos/bin/klist -k $ORCH_DIR/login.keytab | grep '@' | cut -d '@' -f 2 | sed -n '1p'`
    if [ "$JOIN_USER" = "" -o "$DOMAIN_NAME" = "" ];then
        echo "Cannot get username or domain name from keytab file" >> $LOG_FILE
        return $RC
    fi
}

function join_ad()
{	
	echo >> $LOG_FILE
    echo $(date) "Generate Kerberos TGT for adjoin..." >> $LOG_FILE
    echo >> $LOG_FILE

    # Backup and Move default krb5.conf out of the way
    [ -f /etc/krb5.conf ] && mv /etc/krb5.conf /etc/krb5.conf.centrify_backup
    # Generate Kerberos Ticket to adjoin using keytab file
    KRB5_CACHE_LIFETIME=10m
    /usr/share/centrifydc/kerberos/bin/kinit -kt $ORCH_DIR/login.keytab -l $KRB5_CACHE_LIFETIME $JOIN_USER
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to generate Kerberos TGT: $RC" >> $LOG_FILE
        return $RC
    fi

	echo >> $LOG_FILE
    echo $(date) "Joining Active Directory..." >> $LOG_FILE
    echo >> $LOG_FILE

	# Join AD
	/usr/sbin/adjoin \
		--name "$COMPUTER_NAME" \
		--container "$AD_CONTAINER" \
		--zone "$ZONE" \
		--licensetype server \
		"$AD_DOMAIN" \
        >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to join Active Directory: $RC" >> $LOG_FILE
        return $RC
    fi

    # Log status after enrolled
    /usr/bin/adinfo >> $LOG_FILE 2>&1

	# Cleanup 
	/usr/share/centrifydc/kerberos/bin/kdestroy
	if [ -e $ORCH_DIR/login.keytab ];then
      rm -rf $ORCH_DIR/login.keytab
    fi

    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to get status after adjoin: $RC" >> $LOG_FILE
        return $RC
    fi
}

function update_addns()
{
	echo >> $LOG_FILE
    echo $(date) "Updating Active Directory DNS..." >> $LOG_FILE
    echo >> $LOG_FILE
	DNS_NAME="$COMPUTER_NAME.$AD_DOMAIN"
	
	/usr/sbin/addns \
		--update \
		--machine \
		--name "$COMPUTER_NAME" \
		--ipaddr "$NETWORK_ADDR" \
		--domain "$AD_DOMAIN" \
        >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to update DNS: $RC" >> $LOG_FILE
        return $RC
    fi	
}

function install_audit()
{	
	echo >> $LOG_FILE
    echo $(date) "Installing Audit Services..." >> $LOG_FILE
    echo >> $LOG_FILE

	# install Centrify Audit
	yum install -y CentrifyDA

    # Log status after enrolled
    /usr/bin/dainfo >> $LOG_FILE 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to get status after installing Centrify Audit: $RC" >> $LOG_FILE
        return $RC
    fi
}

function run()
{
    check_input
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

    get_instance_data
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

	set_hostname
	RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

    get_platform
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

#    install_prerequisites
#    RC=$?
#    if [ "$RC" != "0" ]; then
#        return $RC
#    fi

	install_gcp_logging_agent
	RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

    install_agent
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

    configure_agent
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

    configure_sshd
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

    enroll
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi
    
	echo >> $LOG_FILE
	echo $(date) "Sleep 10s to make sure cclient has started..." >> $LOG_FILE
	echo >> $LOG_FILE
	sleep 10

    vault_root
    RC=$?
    if [ "$RC" != "0" ]; then
        return $RC
    fi

	add_ad_dns
	RC=$?
    if [ "$RC" != "0" ]; then
    	return $RC
    fi
	
    install_centrifydc
    RC=$?
    if [ "$RC" != "0" ]; then
    	return $RC
    fi
    
    get_keytab_file
    RC=$?
    if [ "$RC" != "0" ]; then
    	return $RC
    fi

    get_user_and_domain
    RC=$?
    if [ "$RC" != "0" ]; then
    	return $RC
    fi

	join_ad
    RC=$?
    if [ "$RC" != "0" ]; then
    	return $RC
    fi

	update_addns
	RC=$?
	if [ "$RC" != "0" ]; then
		return $RC
	fi
	
#    install_audit
#    RC=$?
#    if [ "$RC" != "0" ]; then
#    	return $RC
#    fi
}

function before_enter()
{
    umask 0077

    if [ ! -d $TEMP_DIR ]; then
        echo "Temp directory does not exist"
        exit 1
    fi

    mkdir -p $ORCH_DIR 2>&1
    RC=$?
    if [ "$RC" != "0" ]; then
        echo "Failed to create directory for orchestration: $RC"
        exit $RC
    fi
}

function before_exit()
{
    echo >> $LOG_FILE

    if [ "$1" == "0" ]; then
        echo $(date) "Finished orchestration successfully" >> $LOG_FILE
    else
        echo $(date) "Finished orchestration with error $1" >> $LOG_FILE
    fi

    echo >> $LOG_FILE
    echo "================= Exit =================" >> $LOG_FILE

    exit $1
}

function enter()
{
    before_enter

    echo >> $LOG_FILE
    echo "================= Enter ================" >> $LOG_FILE
    echo >> $LOG_FILE
    echo $(date) "Start orchestration" >> $LOG_FILE
    echo >> $LOG_FILE
    chmod 644 $LOG_FILE
}


# >>> MAIN >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

enter

run
RC=$?
if [ "$RC" != "0" ]; then
    before_exit $RC
fi

#
# Exit
#

before_exit 0
