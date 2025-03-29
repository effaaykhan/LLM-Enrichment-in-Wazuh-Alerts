#!/bin/bash
# Wazuh - YARA active response
# Copyright (C) 2015-2024, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


#------------------------- Configuration -------------------------#

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

# Python script path for LLM integration
PYTHON_SCRIPT="/var/ossec/active-response/bin/llm_query.py"

#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

size=0
actual_size=$(stat -c %s ${FILENAME})
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s ${FILENAME})
done

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-YARA: ERROR - YARA active response error. YARA path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute YARA scan on the specified filename
YARA_output="$("${YARA_PATH}"/yara -w -r -m "$YARA_RULES" "$FILENAME")"

if [[ $YARA_output != "" ]]
then
    # Attempt to delete the file if any YARA rule matches
    if rm -rf "$FILENAME"; then
        echo "wazuh-YARA: INFO - Successfully deleted $FILENAME" >> ${LOG_FILE}
    else
        echo "wazuh-YARA: INFO - Unable to delete $FILENAME" >> ${LOG_FILE}
    fi

    # Flag to check if API request is invalid
    api_request_invalid=false

    # Iterate every detected rule
    while read -r line; do
        # Extract the description from the line using regex
        description=$(echo "$line" | grep -oP '(?<=description=").*?(?=")')
        if [[ $description != "" ]]; then
            # Query the Python LLM script for more information
            llm_response=$(python3 "$PYTHON_SCRIPT" "In one paragraph, tell me about the impact and how to mitigate $description")

            # Check for invalid API response
            if [[ $? -ne 0 ]]; then
                api_request_invalid=true
                echo "wazuh-YARA: ERROR - Invalid LLM API request" >> ${LOG_FILE}
                # Log Yara scan result without LLM response
                echo "wazuh-YARA: INFO - Scan result: $line | chatgpt_response: none" >> ${LOG_FILE}
            else
                # Check if the response text is empty and handle the error
                if [[ -z "$llm_response" ]]; then
                    echo "wazuh-YARA: ERROR - LLM API returned empty response" >> ${LOG_FILE}
                else
                    # Combine the YARA scan output and LLM response
                    combined_output="wazuh-YARA: INFO - Scan result: $line | chatgpt_response: $llm_response"

                    # Append the combined output to the log file
                    echo "$combined_output" >> ${LOG_FILE}
                fi
            fi
        else
            echo "wazuh-YARA: INFO - Scan result: $line" >> ${LOG_FILE}
        fi
    done <<< "$YARA_output"

    # If API request was invalid, log a specific message
    if $api_request_invalid; then
        echo "wazuh-YARA: INFO - API request is invalid. LLM response omitted." >> ${LOG_FILE}
    fi
else
    echo "wazuh-YARA: INFO - No YARA rule matched." >> ${LOG_FILE}
fi

exit 0;
