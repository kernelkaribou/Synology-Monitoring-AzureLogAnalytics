## Synology-Monitoring-AzureLogAnalytics
Simple Python script for Synology NAS SNMP metrics and sending to Azure Log Analytics, part of [Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/)


###### Requirements
* Azure Log Analytics Workspace
* Synology NAS


###### Setup
The script is best suited to run on the NAS itself and highly recommended. It can be ran on another device but the device would need to be able to run python scripts, able to make SNMP calls such as using snmpwal. With minimal configuration, the Synology NAS should be more than capable of capturing this itself.

1. Save the script to a known location on the NAS. For example, /volume1/Local/Scripts/syno_monitor_azure.py 
2. Update the script to have your Azure Log Analytics Workspace ID and Shared Key. This can be found in the Advanced settings of your Azure Log Analytics Workspace > Connected Sources.
3. Modify any other configuration settings, each should have an explanation.
4. On the Synology NAS, Select Control Panel > Terminal & SNMP > SNMP and enable SNMP V1, V2c service.
5. On the Synology NAS, Select Package Center > All Packages > Python Module > Install and follow the prompts.
6. On the Synology NAS, Select Control Panel > Task Scheduler > Create >> Scheduled Task >> User-defined Script.
7. Give the Task a recognizable name.
8. On the Task Settings, set the Run command to *python /path/to/syno_monitor_azure.py*
9. On the Schedule:
   * Run on the following days: **Daily**
   * First run time: **00:00**
   * Frequency: **Every minute**
   * Last run time: **23:59**
10. Query the logs in [Azure Monitor Logs](https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/get-started-queries)
   * The default setting for the custom log space is 'SynoMon' however Azure appends '\_CL' to all custom log entries to avoid potential overwriting of reserved logs.  An example of a query to see all metrics in the last hour:
  
*SynoMon_CL
| where TimeGenerated > ago(1h)
| project ["TimeStamp"]=TimeGenerated, Computer, ["Category"]=ObjectName_s, ["Instance"]=InstanceName_s, ["Counter"]=CounterName_s,  ["Value"]=CounterValue_d
| order by TimeStamp*

