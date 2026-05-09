#####################################################
# securitylog_agent.py
# 
# Agent to run security queries on OCI tenancy audit logs 
# stored in an ADB instance based on security profile 
# provided to the LLM
#
# npotlapa@alumni.princeton.edu
#####################################################

import os
import socket
import sys
import subprocess
import time
from pathlib import Path

import aisuite as ai
from aisuite.mcp import MCPClient

from dotenv import load_dotenv

from llm_functions import print_llm_response, print_intermediate_msgs, llm_token_usage

import warnings
warnings.filterwarnings(
    "ignore",
    message='Field name "schema".*shadows an attribute in parent "BaseModel"',
    category=UserWarning
)

# Initialize env variables
#
load_dotenv()
if not os.getenv("ANTHROPIC_API_KEY"):
    raise ValueError("ANTHROPIC_API_KEY env variable not set")
ANTHROPIC_API_KEY: str | None = os.getenv("ANTHROPIC_API_KEY")

if not os.getenv("OPENAI_API_KEY"):
    raise ValueError("OPENAI_API_KEY env variable not set")
OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")

UVX_PATH: str | None = os.getenv("UVX_PATH", "uvx")
SQL_PATH: str | None = os.getenv("SQL_PATH", "sql")
TNS_PATH: str | None = os.getenv("TNS_PATH")

# models to use
#
models = ["anthropic:claude-sonnet-4-6", "openai:gpt-4.1"]

# print colors
#
RED = "\033[31m"
BLUE = "\033[34m"
RESET = "\033[0m"

def run_security_prompt(label: str, prompt: str, tools, model: str, max_turns: int = 15):    
    print(f"{RED}={'='*60}{RESET}")
    print(f"{RED}STEP: {label}{RESET}")
    print(f"{prompt}")
    messages = [{"role": "system", "content": system_str},
                {"role": "user", "content": prompt}]
    response = client.chat.completions.create(
                model=model, 
                messages=messages, 
                tools=tools, 
                max_turns=max_turns)
    print(f"{RED}={RESET}"*60)
    print(f"{RED}RESULTS: {RESET}")
    print(f"{RED}={RESET}"*60)
    print(f"{BLUE}")
    print(response.choices[0].message.content)
    print(f"{RESET}")
    print(f"{RED}={RESET}"*60)
    return response

# Initialize mcp client and mcp memory 
#
mcp_client = MCPClient(
        command=UVX_PATH,
        args=["oracle.oci-api-mcp-server@latest"]
        )

memory_file = os.path.join(os.getcwd(), "oci_securitylog_skills.jsonl")
file_path = Path(memory_file)
if file_path.exists() and file_path.is_file():
    file_path.unlink()
    print("Deleted existing file: ")
else:
    print("Memory file created: ")
print(memory_file)

memory_mcp = MCPClient(
        command="npx",
        args=["-q", "-y", "@modelcontextprotocol/server-memory"],
        env ={"MEMORY_FILE_PATH": memory_file},
        name="memory"
        )

mcp_db = MCPClient(
        command=SQL_PATH,
        args=["-q", "-mcp"],
        env ={"TNS_ADMIN" : TNS_PATH}
        )

# Print status of the MCP client
print(f"Connected to MCP server: {mcp_client}")
print(f"Connected to MCP memory server: {memory_mcp}")
print(f"Connected to MCP DB: {mcp_db}")

print(f"\nAvailable SQL MCP tools:")
for tool in mcp_db.list_tools():
    print(f"    - {tool['name']}")

mcp_tools = mcp_client.get_callable_tools()
mcp_db_tools = mcp_db.get_callable_tools()
all_tools = mcp_tools + mcp_db_tools + memory_mcp.get_callable_tools()  

# Create aisuite client
#
client = ai.Client()

# Create OCI security profile file
#
system_str = """
You are a security expert with deep experience in Oracle cloud infrastructure logs. Your job is to analyze logs from Oracle Cloud Infrastructure (OCI) tenancy and answer security queries
"""
messages = [
          {"role":"system","content": system_str},
          {"role":"user", "content":"""
           Below is the OCI tenancy security log evaluation profile. Store this security log evaluation profile in memory:

           **Objective**
           Respond to prompts by analyzing security logs stored in an Autonomous database (ADB)

           **Security Logs**
           - OCI Audit Logs: These logs capture all API calls and events in a OCI tenancy. Audit log fields relevant to security queries are,
                 - eventID: UUID of the event
                 - eventTime: Time of the event in RFC3339 timestamp
                 - eventType: Type of event that happened
                 - source: The resource that produced the event
                 - compartmentId: OCID of the compartment of the resource emitting the event
                 - compartmentName: name of the compartment of the resource emitting the event
                 - eventName: Name of the API operation that generated this event
                 - resourceId: OCID or an ID for the resource emitting the event
                 - resourceName: name of the resource emitting the event.
                 - identity_ipAddress: IP address of the source of the request or event
                 - identity_principalId: OCID of the user or service principal who created the event  
                 - identity_principalName: name of the user or service. This value is the friendly name associated with principalId.
                 - tenantId: OCID of the tenant

          ** Audit table schema**
          - Below is the Audit table schema
            - CE_ID                                            VARCHAR2(4000)                 
            - CE_TYPE                                          VARCHAR2(4000)                 
            - CE_SOURCE                                        VARCHAR2(4000)                 
            - CE_TIME                                          TIMESTAMP(6) WITH TIME ZONE    
            - CE_SPECVERSION                                   NUMBER                         
            - CE_DATASCHEMA                                    NUMBER                         
            - INGESTED_MS                                      NUMBER                         
            - INGESTED_ISO                                     TIMESTAMP(6) WITH TIME ZONE    
            - ORACLE_COMPARTMENTID                             VARCHAR2(4000)                 
            - ORACLE_TENANTID                                  VARCHAR2(4000)                 
            - ORACLE_LOGGROUPID                                VARCHAR2(4000)                 
            - ORACLE_INGESTEDTIME                              TIMESTAMP(6) WITH TIME ZONE    
            - EVENTNAME                                        VARCHAR2(4000)                 
            - MESSAGE                                          VARCHAR2(4000)                 
            - COMPARTMENTID                                    VARCHAR2(4000)                 
            - COMPARTMENTNAME                                  VARCHAR2(4000)                 
            - AVAILABILITYDOMAIN                               VARCHAR2(4000)                 
            - RESOURCEID                                       VARCHAR2(4000)                 
            - EVENTGROUPINGID                                  VARCHAR2(4000)                 
            - IDENTITY_PRINCIPALID                             VARCHAR2(4000)                 
            - IDENTITY_PRINCIPALNAME                           VARCHAR2(4000)                 
            - IDENTITY_IPADDRESS                               VARCHAR2(4000)                 
            - IDENTITY_USERAGENT                               VARCHAR2(4000)                 
            - IDENTITY_AUTHTYPE                                VARCHAR2(4000)                 
            - IDENTITY_CALLERID                                VARCHAR2(4000)                 
            - IDENTITY_CALLERNAME                              VARCHAR2(4000)                 
            - IDENTITY_TENANTID                                VARCHAR2(4000)                 
            - REQUEST_ID                                       VARCHAR2(4000)                 
            - REQUEST_ACTION                                   VARCHAR2(4000)                 
            - REQUEST_PATH                                     VARCHAR2(4000)                 
            - REQUEST_PARAMETERS                               VARCHAR2(32767)                
            - REQUEST_OPCREQUESTID                             VARCHAR2(4000)                 
            - RESPONSE_STATUS                                  NUMBER                         
            - RESPONSE_RESPONSETIME                            TIMESTAMP(6) WITH TIME ZONE    
            - RESPONSE_MESSAGE                                 VARCHAR2(32767)                
            - RESPONSE_PAYLOAD                                 VARCHAR2(32767)                
            - ADDITIONALDETAILS_NAMESPACE                      VARCHAR2(4000)                 
            - DEFINEDTAGS                                      VARCHAR2(4000)                 
            - FREEFORMTAGS                                     VARCHAR2(4000)                 
            - STATECHANGE_CURRENT                              VARCHAR2(32767)                
            - STATECHANGE_PREVIOUS                             VARCHAR2(32767)                
            - ADDITIONALDETAILS_BUCKETNAME                     VARCHAR2(4000)                 
            - ADDITIONALDETAILS_X_REAL_PORT                    NUMBER                         
            - ADDITIONALDETAILS_DESCRIPTION                    VARCHAR2(4000)                 
            - ADDITIONALDETAILS_ISACCESSABLE                   VARCHAR2(4000)                 
            - ADDITIONALDETAILS_LIFECYCLESTATE                 VARCHAR2(4000)                 
            - ADDITIONALDETAILS_HOMEREGIONKEY                  VARCHAR2(4000)                 
            - ADDITIONALDETAILS_ACTORDISPLAYNAME               VARCHAR2(4000)                 
            - ADDITIONALDETAILS_ACTORID                        VARCHAR2(4000)                 
            - ADDITIONALDETAILS_ACTORNAME                      VARCHAR2(4000)                 
            - ADDITIONALDETAILS_ACTOROCID                      VARCHAR2(4000)                 
            - ADDITIONALDETAILS_AUDITEVENTMAPVALUE             VARCHAR2(32767)                
            - ADDITIONALDETAILS_CLIENTIP                       VARCHAR2(4000)                 
            - ADDITIONALDETAILS_DOMAINDISPLAYNAME              VARCHAR2(4000)                 
            - ADDITIONALDETAILS_DOMAINID                       VARCHAR2(4000)                 
            - ADDITIONALDETAILS_DOMAINNAME                              VARCHAR2(4000)     
            - ADDITIONALDETAILS_ECID                                    VARCHAR2(4000)     
            - ADDITIONALDETAILS_EVENTID                                 VARCHAR2(4000)     
            - ADDITIONALDETAILS_ID                                      VARCHAR2(4000)     
            - ADDITIONALDETAILS_IDCSCREATEDBY                           VARCHAR2(4000)     
            - ADDITIONALDETAILS_IDCSLASTMODIFIEDBY                      VARCHAR2(4000)     
            - ADDITIONALDETAILS_META                                    VARCHAR2(4000)     
            - ADDITIONALDETAILS_METERASOPCSERVICE                       VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSOAPPLICATIONID                        VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSOAPPLICATIONNAME                      VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSOAPPLICATIONTYPE                      VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSOIDENTITYPROVIDER                     VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSOIDENTITYPROVIDERTYPE                 VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSOMATCHEDSIGNONPOLICY                  VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSORP                                   VARCHAR2(4000)     
            - ADDITIONALDETAILS_SSOSESSIONCREATETIME                    NUMBER             
            - ADDITIONALDETAILS_SSOSESSIONID                            VARCHAR2(4000)     
            - ADDITIONALDETAILS_TIMESTAMP                               NUMBER             
            - ADDITIONALDETAILS_ADMINRESOURCEID                         VARCHAR2(4000)     
            - ADDITIONALDETAILS_ADMINRESOURCENAME                       VARCHAR2(4000)     
            - ADDITIONALDETAILS_ADMINRESOURCEOCID                       VARCHAR2(4000)     
            - ADDITIONALDETAILS_ADMINRESOURCETYPE                       VARCHAR2(4000)     
            - ADDITIONALDETAILS_ADMINVALUESADDED                        VARCHAR2(32767)    
            - ADDITIONALDETAILS_ADMINVALUESREMOVED                      VARCHAR2(32767)    
            - ADDITIONALDETAILS_CLIENTSTRIPENAME                        VARCHAR2(4000)     
            - ADDITIONALDETAILS_NOTIFICATIONDELIVERYCHANNEL             VARCHAR2(4000)     
            - ADDITIONALDETAILS_NOTIFICATIONPUSHREQUESTID               VARCHAR2(4000)     
            - ADDITIONALDETAILS_COMPARTMENTID                           VARCHAR2(4000)     
            - ADDITIONALDETAILS_DEFINEDTAGS                             VARCHAR2(4000)     
            - ADDITIONALDETAILS_DISPLAYNAME                             VARCHAR2(4000)     
            - ADDITIONALDETAILS_FREEFORMTAGS                            VARCHAR2(4000)     
            - ADDITIONALDETAILS_SYSTEMTAGS                              VARCHAR2(4000)     
            - ADDITIONALDETAILS_TARGETCOMPARTMENTID                     VARCHAR2(4000)     
            - ADDITIONALDETAILS_TARGETTYPE                              VARCHAR2(4000)     
            - ADDITIONALDETAILS_IMAGEID                                 VARCHAR2(32767)    
            - ADDITIONALDETAILS_SHAPE                                   VARCHAR2(32767)    
            - ADDITIONALDETAILS_TYPE                                    VARCHAR2(32767)    

           **Workflow**
           Below are the instructions to connect to ADB instance with Audit events and run SQL queries to answer input prompts
            - OCI Audit logs are stored in DB tables with names starting with 'AUDIT_LOGS_'. If you cannot find the table, use this table name 'AUDIT_LOGS_20260304_16_17_UTC'
            - Connect to the ADB instance using the 'connect' tool in SQLcl MCP using the named connection. Named connection for the ADB instance is 'oci_adb'
            - Construct a SQL query to get information required for the input prompt. Use the input prompt, audit table name and audit table schema to contruct the SQL query
            - Execute the SQL query using 'run-sql' tool
            - Format the information returned to answer the input prompt

           Summarize the above information to me.
           """
           }
        ]

try:
    response = client.chat.completions.create(
            model=models[0],
            messages=messages,
            tools=all_tools,
            max_turns=5
            )

    # print colors
    #
    RED = "\033[31m"
    BLUE = "\033[34m"
    RESET = "\033[0m"

    print(f"{RED}={RESET}"*60)
    print(f"{RED}OCI AUDIT LOG ANALYSIS PROFILE{RESET}")
    print(f"{RED}={RESET}"*60)
    print(f"{BLUE}")
    print(response.choices[0].message.content)
    print(f"{RESET}")
    print(f"{RED}={RESET}"*60)

    # Print token usage
    llm_token_usage(response)


    # Make security log queries
    #
    security_prompts = {
            "Query1":"List the user tables in the ADB instance storing audit events. Retrieve instructions from security log evaluation profile stored in memory",
            "Query2":"List all the IP addresses of the audit events. Audit events are stored in a table in the ADB instance. Retrieve instructions from security log evaluation profile stored in memory.",
            "Query3":"List all identity principals for the audit events. Audit events are stored in a table in the ADB instance. Retrieve instructions from security log evaluation profile stored in memory."
    }


    for query, prompt in security_prompts.items():
        label = f"{query} processing"
        model = models[0]
        tools = all_tools
        max_turns = 15
    
        response = run_security_prompt(label, prompt, tools, model, max_turns)
        llm_token_usage(response)

finally:
    # Close MCP connections
    #
    mcp_client.close()
    mcp_db.close()
    memory_mcp.close()
    print("MCP connection closed")



