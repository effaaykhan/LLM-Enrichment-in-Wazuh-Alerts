# LLM-Enrichment-in-Wazuh-Alerts

# Ubuntu 22.04 Endpoint
## ➡️ Step 1: Yara Installation
   ## - Install Dependencies
      
      apt-get install automake libtool make gcc pkg-config
      apt-get install flex bison
      apt install libjansson-dev
      apt install libmagic-dev
   
  ## - Install Yara
      
      wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.1.tar.gz
      tar xzvf v4.5.1.tar.gz
      cd yara-4.5.1
      ./bootstrap.sh
      ./configure --enable-cuckoo --enable-magic --enable-dotnet
      make
      make install
      make check
      

## ➡️ Step 2: Install Yara Rules
      cd /opt/yara-4.5.1/rules
      ./index_gen.sh

## ➡️ Step 3: Now add the following scripts in /var/ossec/active-response/bin
   - [yara.sh](https://github.com/effaaykhan/LLM-Enrichment-in-Wazuh-Alerts/blob/main/yara.sh)
   - [llm_query.py](https://github.com/effaaykhan/LLM-Enrichment-in-Wazuh-Alerts/blob/main/llm_query.py)

## ➡️ Wazuh-Server Config
   - Paste the [Decoders](https://github.com/effaaykhan/LLM-Enrichment-in-Wazuh-Alerts/blob/main/local_decoder.xml) in /var/ossec/etc/decoders/local_decoder.xml
   - Paste the [Rules](https://github.com/effaaykhan/LLM-Enrichment-in-Wazuh-Alerts/blob/main/local_rules.xml) in /var/ossec/etc/rules/local_rules.xml
   - In [ossec.conf](https://github.com/effaaykhan/LLM-Enrichment-in-Wazuh-Alerts/blob/main/ossec.conf) Add the following block
      
