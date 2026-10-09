-- Cloud IR — CloudTrail investigation queries (Athena)
-- Replace the partition/table name with your CloudTrail Athena table.

-- 1) Everything a suspect access key did, in order (the kill chain)
SELECT eventtime, eventname, sourceipaddress, awsregion, useragent,
       errorcode, requestparameters
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIA...EXAMPLE'
ORDER BY eventtime;

-- 2) First-seen vs normal: all source IPs this identity has ever used
SELECT sourceipaddress, min(eventtime) first_seen, max(eventtime) last_seen, count(*) n
FROM cloudtrail_logs
WHERE useridentity.arn LIKE '%<username>%'
GROUP BY sourceipaddress
ORDER BY first_seen DESC;

-- 3) Privilege-escalation signals
SELECT eventtime, eventname, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('CreateRole','AttachRolePolicy','PutUserPolicy','AttachUserPolicy',
                    'CreateAccessKey','CreateUser','CreateLoginProfile','PassRole')
  AND eventtime > timestamp '2026-02-10 03:00:00'
ORDER BY eventtime;

-- 4) S3 exfiltration (needs S3 data events enabled)
SELECT eventtime, eventname, sourceipaddress,
       json_extract_scalar(requestparameters,'$.bucketName') bucket,
       json_extract_scalar(requestparameters,'$.key') object
FROM cloudtrail_logs
WHERE eventname IN ('GetObject','ListObjects','CopyObject')
  AND useridentity.accesskeyid = 'AKIA...EXAMPLE'
ORDER BY eventtime;

-- 5) Did they touch CloudTrail/GuardDuty (anti-forensics)?
SELECT eventtime, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging','DeleteTrail','UpdateTrail',
                    'DeleteDetector','UpdateDetector')
ORDER BY eventtime;
