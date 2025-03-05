# Splunk Defensive Solution

## Description  
This project involves setting up and utilizing Splunk as a security monitoring solution to investigate cyberattacks. The objective will be to analyze logs from Windows and Apache servers, detect suspicious activities, and assess the effectiveness of security measures. Tasks include log ingestion, report generation, alert configuration, dashboard creation, and incident analysis to identify threats and anomalies. 

## Key Components  
- **Splunk** for log analysis, reporting, and alert configuration  
- **Apache Server Logs** and **Windows Logs** for investigating web and system-based attacks  
- **Linux Server** for hosting the environment and analyzing logs  
- **SIEM System** for threat detection and optimization  

## Skills Gained and Exercised  

- **Log Analysis and Threat Detection**  
  - Learned to ingest, search, and analyze logs using Splunk to detect security incidents, unauthorized access, and system anomalies.

- **Security Monitoring and Incident Response**  
  - Developed skills in monitoring critical systems, identifying attack patterns, and responding to security breaches by analyzing attack logs.

- **Report Generation and Data Interpretation**  
  - Created and analyzed Splunk reports to understand security trends, detect anomalies, and assess the severity of threats.

- **Alert Configuration and Tuning**  
  - Configured Splunk alerts to detect suspicious login attempts, failed access activities, and privilege escalation attempts.

- **Dashboard Creation and Visualization**  
  - Built interactive dashboards to visualize attack data, monitor critical security metrics, and enhance decision-making for threat mitigation.

- **Account Security and Suspicious Activity Detection**  
  - Monitored logs for unusual user behavior, such as failed logins and unauthorized access, to detect potential account compromises.

- **HTTP Traffic and Web Server Attack Analysis**  
  - Investigated Windows and Apache attack logs, analyzed HTTP methods, referrer domains, and response codes to detect potential web-based attacks.

- **SIEM Configuration and Optimization**  
  - Gained hands-on experience in configuring a Security Information and Event Management (SIEM) solution, optimizing search queries, and ensuring accurate threat detection.


---

# Splunk Defensive Solution: Normal Activity

## Part 1: Loaded and Analyzed Windows Logs

- **Uploaded Windows security logs**: Used the "Add Data" option in Splunk to upload the `windows_server_logs.csv` file from the `/splunk/logs/Week-2-Day-3-Logs/` directory.
- **Configured data input**: Set the host name to “Windows_server_logs” and successfully submitted the data.
- **Analyzed logs**: Briefly reviewed logs and fields, focusing on the following:
  - `signature_id`
  - `signature`
  - `user`
  - `status`
  - `severity`

![Screenshot 2025-02-24 at 7 55 27 PM](https://github.com/user-attachments/assets/c49aad4e-33c1-4432-9583-c0a502839c07)
![Screenshot 2025-02-24 at 7 58 07 PM](https://github.com/user-attachments/assets/2bc6fdfe-90c6-4927-a682-9147d246ad4d)
![Screenshot 2025-02-24 at 8 00 17 PM](https://github.com/user-attachments/assets/3445b7c9-5059-4257-a86c-cdd29392e939)



## Part 2: Created Reports, Alerts, and Dashboards for Windows Logs

### Reports
- **Signature Report**: Created a report with a table of signatures and associated signature IDs to identify specific Windows activity.
  - Removed duplicate values in the SPL search for accurate results.
- **Severity Report**: Designed a report to display severity levels with counts and percentages of each.
- **Success/Failure Report**: Developed a report comparing successful and failed Windows activities using the "status" field.

![Screenshot 2025-02-24 at 8 50 31 PM](https://github.com/user-attachments/assets/55b68041-5448-41ac-8406-03101e80128a)


### Alerts
- **Failed Activity Alert**: Established a baseline and threshold for hourly failed Windows activity, triggering an alert when exceeded. This alert is configured to send an email to `SOC@VSI-company.com`.
- **Successful Login Alert**: Defined a baseline and threshold for the hourly count of the signature “an account was successfully logged on,” creating an alert based on signature ID.
- **Account Deletion Alert**: Set up an alert for the hourly count of the signature “a user account was deleted,” based on the signature ID.

![Screenshot 2025-02-24 at 9 43 05 PM](https://github.com/user-attachments/assets/eb194ef0-257d-487e-b1d5-545f6f76d86d)
![Screenshot 2025-03-04 at 5 20 56 PM](https://github.com/user-attachments/assets/7f30b2d2-6dbb-4bd3-ad48-c687a1087789)


### Visualizations and Dashboards
- **Line Chart for Signatures**: Created a line chart displaying different “signature” field values over time (`timechart span=1h count by signature`).
- **Line Chart for Users**: Developed a line chart displaying different “user” field values over time.
- **Signature Count Visualization**: Added a visualization showing the count of different signatures.
- **User Count Visualization**: Created a visualization illustrating the count of different users.
- **Single-Value Visualization**: Designed a custom visualization (e.g., radial gauge or marker gauge) analyzing a single data point.

All visualizations were added to the **Windows Server Monitoring** dashboard with the ability to change the time range. Panels were appropriately titled and organized.

![Screenshot 2025-02-25 at 5 24 43 PM](https://github.com/user-attachments/assets/793289c0-e23f-40b5-859b-e6cef17e16c0)

## Part 3: Loaded and Analyzed Apache Logs

- **Uploaded Apache logs**: Used the "Add Data" option in Splunk to upload the `apache_logs.txt` file from the `/splunk/logs/Week-2-Day-3-Logs/` directory.
- **Configured data input**: Set the host name to “Apache_logs” and submitted the data.
- **Analyzed logs**: Reviewed logs and fields, focusing on:
  - `method`
  - `referer_domain`
  - `status`
  - `clientip`
  - `useragent`

![Screenshot 2025-02-25 at 6 13 24 PM](https://github.com/user-attachments/assets/0889763d-c53b-4cbc-9377-d7512813665b)
![Screenshot 2025-02-25 at 6 14 18 PM](https://github.com/user-attachments/assets/4c7a8140-dc50-48a0-9d7e-8ee18018eea9)
![Screenshot 2025-02-25 at 6 14 49 PM](https://github.com/user-attachments/assets/92f3c4a1-1e18-4b87-b24d-5cbaafca29a8)


## Part 4: Created Reports, Alerts, and Dashboards for Apache Logs

### Reports
- **HTTP Methods Report**: Created a report displaying a table of different HTTP methods (GET, POST, HEAD, etc.).
- **Top Referrers Report**: Designed a report to show the top 10 domains referring to VSI’s website.
- **HTTP Response Codes Report**: Developed a report showing the count of each HTTP response code.

![Screenshot 2025-02-25 at 6 23 59 PM](https://github.com/user-attachments/assets/a700473b-b6eb-4711-9868-33b6290465fe)


### Alerts
- **Non-US Activity Alert**: Established a baseline and threshold for hourly activity from countries other than the United States. Configured the alert to trigger when the threshold is exceeded, sending an email to `SOC@VSI-company.com`.
- **HTTP POST Method Alert**: Set a baseline and threshold for the hourly count of HTTP POST method activity and configured the alert accordingly.

![Screenshot 2025-02-25 at 6 37 32 PM](https://github.com/user-attachments/assets/e6e87f99-03bd-4017-96d4-43ffa84bf048)


### Visualizations and Dashboards
- **Line Chart for HTTP Methods**: Created a line chart displaying different HTTP “methods” field values over time (`timechart span=1h count by method`).
- **Geographical Map for Client IPs**: Developed a geographical map visualizing the location based on the “clientip” field.
- **URI Count Visualization**: Added a visualization displaying the count of different URIs.
- **Top Countries Visualization**: Designed a visualization illustrating the top 10 countries from the log data.
- **User Agents Visualization**: Created a visualization showing the count of different user agents.

These visualizations were added to the **Apache Web Server Monitoring** dashboard, with the ability to change the time range for each panel. Panels were titled and organized.

![Screenshot 2025-02-27 at 10 38 57 AM](https://github.com/user-attachments/assets/a77509f6-570c-46b9-ac31-9b2df4d82a12)
![Screenshot 2025-02-27 at 10 39 21 AM](https://github.com/user-attachments/assets/c4ae0dcb-6d46-4e5a-aa5d-0a0f9ba8c5c4)


## Part 5: Installed an Add-On Splunk Application for Additional Monitoring

- **Chosen Add-On App**: Selected the Splunk Add-On for Apache Servers for additional security monitoring of VSI’s systems.
- **Installed and Configured Add-On**: Installed the add-on app and described how its features would help protect VSI.
- **Scenario**: Provided a use case showing how the add-on app helps with security monitoring.


---


# Splunk Defensive Solution: Attack Activity


## Part 1: Analyze Windows Attack Logs

### Task 1: Report Analysis for Severity

![Screenshot 2025-02-27 at 1 18 16 PM](https://github.com/user-attachments/assets/f4305d93-cc7f-4e88-bc70-625393b88add)

### Findings
- There was a signficant increase in `high` severity events during the attack (329 to 1111).

### Task 2: Report Analysis for Failed Activities

![Screenshot 2025-02-27 at 1 21 23 PM](https://github.com/user-attachments/assets/0766bed1-83bb-4a49-aa19-54d6a4f7eb5c)

### Findings
- There was a notable increase in `success` events during the attack (4622 to 5856).
- There was a slight decrease in `failure` events during the attack (142 to 93)

### Task 3: Alert Analysis for Failed Windows Activity

![Screenshot 2025-03-04 at 6 58 21 PM](https://github.com/user-attachments/assets/7acbf927-3b59-46a2-846b-f041aa23dd36)

### Findings
- There was a spike in `failure` events during the attack, specifically at 8:00 am.

### Task 4: Alert Analysis for Successful Logins

![Screenshot 2025-03-04 at 10 38 30 PM](https://github.com/user-attachments/assets/7ba56019-c4f9-4b67-a8ca-a4e1a5021ca5)

### Findings
- There was no evidence of an unusual amount of successful logins based on signature ID. The threshold for this alert was set to >20 events.

### Task 5: Alert Analysis for Deleted Accounts

![Screenshot 2025-03-04 at 10 42 29 PM](https://github.com/user-attachments/assets/3805986a-2138-47d5-a853-96bdf9379f8b)

### Findings
- There was no evidence of an unusual amount of deleted accounts. The threshold for this alert was set to >22 events.



### Windows Attack Dashboard

![Screenshot 2025-02-27 at 3 56 23 PM](https://github.com/user-attachments/assets/c603f723-4e65-4f02-adda-21f97c1d9296)


### Task 7: Dashboard Analysis for Time Chart of Signatures

![Screenshot 2025-03-03 at 12 15 28 PM](https://github.com/user-attachments/assets/b711cc89-16ed-445c-a945-025743304026)
![Screenshot 2025-03-03 at 12 15 49 PM](https://github.com/user-attachments/assets/702e93a2-57e7-4f75-86ab-8c09912b22c6)
![Screenshot 2025-03-03 at 12 16 03 PM](https://github.com/user-attachments/assets/f6c9a7ed-a628-4d9d-a861-d3647a403a38)

### Findings
- Notable signatures:
  - `A user account was locked out` | Timeframe: 1:00 am - 2:00 am | Peak Count: 896
  - `An attempt was made to reset an accounts password` | Timeframe: 9:00 am - 10:00 am | Peak Count: 1258
  - `An account was successfully logged on` | Timeframe: 11:00 am | Peak Count: 196
- The signature ID for Windows Successful Login did not match the label for `An account was successfully logged on` in the dataset and therefore did not trigger an alert.

### Task 8: Dashboard Analysis for Users

![Screenshot 2025-03-03 at 12 16 26 PM](https://github.com/user-attachments/assets/9e3b0eb4-6950-4a90-a3e7-d02a8dba5bb2)
![Screenshot 2025-03-03 at 12 16 45 PM](https://github.com/user-attachments/assets/cc6bbc72-f496-4d1c-8beb-73243fed0a83)
![Screenshot 2025-03-03 at 12 17 06 PM](https://github.com/user-attachments/assets/a5edba8f-687a-474e-8d0d-c8624ecaf4be)

### Findings
- Notable users:
  - user_a | Timeframe: 1:00 am - 2:00 am | Peak Count: 984
  - user_k | Timeframe: 9:00 am - 10:00 am | Peak Count: 1256
  - user_j | Timeframe: 11:00 am | Peak Count: 196

### Task 9: Dashboard Analysis for Signatures with Bar, Graph, and Pie Charts

![Screenshot 2025-03-03 at 12 17 43 PM](https://github.com/user-attachments/assets/2414366f-6db1-441a-8a39-893e2ddd347b)
![Screenshot 2025-03-03 at 12 18 00 PM](https://github.com/user-attachments/assets/4cb6562a-d8dd-4ebb-87a5-c10f4b0411c5)
![Screenshot 2025-03-03 at 12 18 20 PM](https://github.com/user-attachments/assets/7e0238bb-11f2-44f2-8299-5ce09a554e4a)

### Findings
- The piechart breakdown of the signature count aligns with the findings from the time chart data for signature activity.

### Task 10: Dashboard Analysis for Users with Bar, Graph, and Pie Charts

![Screenshot 2025-03-03 at 12 18 36 PM](https://github.com/user-attachments/assets/aaedb870-3029-43da-88d5-60b0781a3a8b)
![Screenshot 2025-03-03 at 12 18 50 PM](https://github.com/user-attachments/assets/3191921e-978a-4a9d-8799-a3ed2066f45c)
![Screenshot 2025-03-03 at 12 19 09 PM](https://github.com/user-attachments/assets/6a9993d5-4c86-4faa-a86a-9f940ae369f9)

### Findings
- The piechart breakdown of the user activity aligns with the findings from the time chart data for user activity.

### Task 11: Dashboard Analysis for Users with Statistical Charts: Pros & Cons

### Pros
- Detailed View – Shows exact numbers and timestamps for user activity.
- Easy Filtering – You can sort and filter data for deeper analysis.
- Long-Term Tracking – Helps monitor trends over time.
- Consistent Data – Uses signature IDs, avoiding issues with Windows updates.

### Cons
- Harder to Read – A table isn’t as easy to understand as a chart.
- No Visual Trends – Doesn’t highlight patterns at a glance.
- More Manual Work – Requires filtering and analysis to find insights.

### Comparison to Other Panels
- Charts make it easier to spot trends and spikes quickly.
- Pie/Bar Graphs show comparisons at a glance without manual sorting.
- Single-Value Metrics provide instant key stats like failed logins.

---

# Splunk Defensive Solution: Attack Activity


## Part 2: Analyze Apache Attack Logs

### Task 1: Report Analysis for Methods
1. **Accessed the “Reports” tab** and selected the report analyzing HTTP methods.
2. **Opened the report in search mode** by selecting “Edit” > “Open in Search.”
3. **Took note of the percentage and count of various HTTP methods.**
4. **Changed the source from `apache_logs.txt` to `apache_attack_logs.txt`.**
5. **Saved the updated report** with the new source.
6. **Reviewed the updated results** and noted if there were any suspicious changes in HTTP methods.
   - Detected changes in HTTP methods: [Answer here]
   - Method used for the attack: [Answer here]

### Task 2: Report Analysis for Referrer Domains
1. **Accessed the “Reports” tab** and selected the report analyzing referrer domains.
2. **Opened the report in search mode** by selecting “Edit” > “Open in Search.”
3. **Noted the referrer domains** and changed the source from `apache_logs.txt` to `apache_attack_logs.txt`.
4. **Saved the updated report** with the new source.
5. **Reviewed the updated results** and noted if there were any suspicious changes in referrer domains.
   - Detected suspicious changes in referrer domains: [Answer here]

### Task 3: Report Analysis for HTTP Response Codes
1. **Accessed the “Reports” tab** and selected the report analyzing HTTP response codes.
2. **Opened the report in search mode** by selecting “Edit” > “Open in Search.”
3. **Took note of the HTTP response codes** and changed the source from `apache_logs.txt` to `apache_attack_logs.txt`.
4. **Saved the updated report** with the new source.
5. **Reviewed the updated results** and noted if there were any suspicious changes in HTTP response codes.
   - Detected suspicious changes in HTTP response codes: [Answer here]

### Task 4: Alert Analysis for International Activity
1. **Accessed the “Alerts” tab** and selected the alert for suspicious international activity.
2. **Opened the alert in search mode** by selecting “Open in Search.”
3. **Changed the source from `apache_logs.txt` to `apache_attack_logs.txt`.**
4. **Reviewed the alert results** and answered the following questions:
   - Detected suspicious volume of international activity: [Answer here]
   - Count of events in the hour(s): [Answer here]
   - Would the alert be triggered for this activity? [Answer here]
   - Would you change the threshold? [Answer here]

### Task 5: Alert Analysis for HTTP POST Activity
1. **Accessed the “Alerts” tab** and selected the alert for suspicious HTTP POST activity.
2. **Opened the alert in search mode** by selecting “Open in Search.”
3. **Changed the source from `apache_logs.txt` to `apache_attack_logs.txt`.**
4. **Reviewed the alert results** and answered the following questions:
   - Detected suspicious volume of HTTP POST activity: [Answer here]
   - Count of events in the hour(s): [Answer here]
   - When did it occur? [Answer here]
   - Would you change the threshold? [Answer here]

### Dashboard Setup
1. **Accessed the Apache Web Server Monitoring dashboard** and selected “Edit.”
2. For each panel:
   - **Edited the search** to change the source from `apache_logs.txt` to `apache_attack_logs.txt`.
   - **Applied the changes** and saved the updated dashboard.
3. **Set the dashboard time range to “All Time”** for comprehensive analysis.

### Task 6: Dashboard Analysis for Time Chart of HTTP Methods
1. **Analyzed the new dashboard results** and answered the following questions:
   - Did anything stand out as suspicious? [Answer here]
   - Which method seems to be used in the attack? [Answer here]
   - At what times did the attack start and stop? [Answer here]
   - What is the peak count of the top method during the attack? [Answer here]

### Task 7: Dashboard Analysis for Cluster Map
1. **Analyzed the cluster map results** and answered the following questions:
   - Does anything stand out as suspicious? [Answer here]
   - Which new location (city, country) on the map has a high volume of activity? [Answer here]
   - What is the count of that city? [Answer here]

### Task 8: Dashboard Analysis for URI Data
1. **Analyzed the URI data panel** and answered the following questions:
   - Does anything stand out as suspicious? [Answer here]
   - What URI is hit the most? [Answer here]
   - Based on the URI being accessed, what could the attacker potentially be doing? [Answer here]

---


