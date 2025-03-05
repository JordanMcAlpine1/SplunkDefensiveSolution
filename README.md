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

![Screenshot 2025-03-05 at 12 35 36 PM](https://github.com/user-attachments/assets/ff33c81f-28aa-4390-9247-bd9b50b24ef3)

### Findings
- There was a spike in `failure` events during the attack, specifically at 8:00 am. The alert for this actvity would have been triggered as the threshold was set to >11 events.

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

![Screenshot 2025-02-28 at 1 15 53 PM](https://github.com/user-attachments/assets/ce20f0ed-65d2-4046-93df-ff4baeb39999)

### Findings
- There was a significant increase in `POST` HTTP methods during the attack timeframe (106 to 1324).

### Task 2: Report Analysis for Referrer Domains

![Screenshot 2025-02-28 at 1 22 44 PM](https://github.com/user-attachments/assets/bcc5caf6-591a-40ae-862f-808057b1496f)

### Findings
- There was a significant deacrease in the referring domain count during the attack timeframe.
- Top 5 notable changes:
   - `http://www.semicomplete.com` (3038 to 764)
   - `http://semicomplete.com` (2001 to 572)
   - `http://www.google.com` (123 to 37)
   - `https://www.google.com` (105 to 25)
   - `http://stackoverflow.com` (34 to 15)

### Task 3: Report Analysis for HTTP Response Codes

![Screenshot 2025-02-28 at 1 33 22 PM](https://github.com/user-attachments/assets/6bc910ac-0358-4692-beff-6a58a0149166)

### Findings
- There was a significant increase in the `404` HTTP response code count during the attack timeframe (213 to 679).

### Task 4: Alert Analysis for International Activity

![Screenshot 2025-03-05 at 11 25 18 AM](https://github.com/user-attachments/assets/1ac76c70-a2d7-485b-802d-e3a06bd2447f)
![Screenshot 2025-03-05 at 11 25 51 AM](https://github.com/user-attachments/assets/8ea79123-89e6-42d2-9fde-d847e5b1d853)
![Screenshot 2025-03-05 at 11 26 09 AM](https://github.com/user-attachments/assets/06aab7ac-dac1-4a14-ab48-b5492cb47aa4)

### Findings
- There were significant spikes in international activity at 6:00 pm (730) and at 8:00 pm (1415).
- The alert for this activity would have been triggered as the threshold was set to >137 events.


### Task 5: Alert Analysis for HTTP POST Activity

![Screenshot 2025-03-05 at 11 33 13 AM](https://github.com/user-attachments/assets/6928a83d-6fe9-482f-ae54-2382affd5b88)
![Screenshot 2025-03-05 at 11 34 04 AM](https://github.com/user-attachments/assets/57be1703-28f3-477f-9db1-55992ab4496e)

### Findings
- There was a significant spike in HTTP `POST` activity at 8:00 pm (1296).
- The alert for this activity would have been triggered as the threshold was set to >4 events.

### Apache Attack Dashboard

![Screenshot 2025-02-28 at 2 10 56 PM](https://github.com/user-attachments/assets/b381fc9c-d627-419a-8d9d-82b9574d7b9a)
![Screenshot 2025-02-28 at 2 11 28 PM](https://github.com/user-attachments/assets/99218e0c-7a24-4bda-9057-a3d30ff061a5)


### Task 6: Dashboard Analysis for Time Chart of HTTP Methods

![Screenshot 2025-02-28 at 2 12 56 PM](https://github.com/user-attachments/assets/78ae450e-c0c7-40fe-be98-a1a9e672f81b)
![Screenshot 2025-02-28 at 2 13 14 PM](https://github.com/user-attachments/assets/143e372b-da20-475e-a55d-5173b5cb360a)

### Findings
- There was a significant spike in HTTP `GET` activity at 6:00 pm (729).
- There was a significant spike in HTTP `POST` activity at 8:00 pm (1296).

### Task 7: Dashboard Analysis for Cluster Map

![Screenshot 2025-02-28 at 2 22 38 PM](https://github.com/user-attachments/assets/850581be-8014-4325-bfce-52e6d97e2be7)
![Screenshot 2025-02-28 at 2 26 27 PM](https://github.com/user-attachments/assets/afdf0cd3-004b-4af2-be01-ecb7a652202f)

### Findings
- There was a large amount of activity in Ukraine during the attack timeframe. This country does not have a history of high web traffic to the VSI servers and is considered to be abnormal.
- The total number of activities from Ukraine was 432.
- Additional research illustrates that the web traffic originated from Kharkiv, Ukraine.

### Task 8: Dashboard Analysis for URI Data

![Screenshot 2025-02-28 at 2 28 56 PM](https://github.com/user-attachments/assets/33d8be27-821e-443d-9c28-407f5db4c9d4)
![Screenshot 2025-02-28 at 2 29 16 PM](https://github.com/user-attachments/assets/6f8c9b7d-0940-4b1b-9aee-e0286011be72)

### Findings
- The most targeted URI was `/VSI_Account_logon.php`. Additionally the URI `/files/logstash/logstash-1.3.2-monolithic.jar` had a notably higher count relative to the rest of the most frequently accessed URIs.

---

## VSI Web Server Attack Summary

VSI’s web server was hit by a coordinated cyber attack involving brute-force login attempts, reconnaissance scanning, and possible exploitation efforts. A sharp increase in HTTP POST requests, particularly targeting /VSI_Account_logon.php, pointed to a credential stuffing or brute-force attack. Additionally, an unusual spike in traffic from Ukraine suggested the involvement of a foreign threat actor or botnet. The attack also triggered a surge in 404 (Not Found) response codes, indicating that attackers were actively probing for restricted directories and vulnerabilities. The total volume of HTTP requests exceeded normal thresholds, raising concerns about a DDoS or automated high-volume attack. Furthermore, attackers appeared to focus on sensitive URIs and files related to logins and system configurations, potentially aiming for data exfiltration or privilege escalation. Notably, user_a, user_k, and user_j exhibited significant unusual activity, suggesting they were key targets during the attack.


## VSI Future Mitigation Breakdown

To protect VSI from future attacks, several mitigation strategies should be implemented. Strengthening authentication and access controls is crucial—this includes enforcing multi-factor authentication (MFA), increasing password complexity requirements, and limiting login attempts per IP address to prevent credential stuffing and brute-force attacks. Enhancing web application security is also essential, which can be achieved by deploying a Web Application Firewall (WAF) to filter malicious requests and restricting access to sensitive files and endpoints to prevent unauthorized access. Given that the attack involved high-volume traffic from Ukraine, geo-based security policies should be enforced, such as enabling geo-blocking for high-risk countries and monitoring international traffic patterns for anomalies.

To detect and respond to threats in real-time, VSI should improve logging and monitoring by enabling real-time log analysis and deploying an Intrusion Detection System (IDS) to identify suspicious activity. Since the attack involved DDoS-like traffic spikes, mitigation strategies should include leveraging Content Delivery Networks (CDN) to absorb high-volume traffic and using anomaly-based traffic filtering to detect and block unusual request patterns. Additionally, regular security audits and penetration testing should be conducted to proactively identify vulnerabilities, simulate attacks on VSI’s infrastructure, and ensure employees are trained in phishing and social engineering awareness to reduce human-related security risks. Implementing these measures will help VSI harden its security posture and prevent similar attacks in the future.
