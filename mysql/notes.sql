# Move old records to old database

INSERT INTO arpdata_old SELECT * FROM arpdata WHERE DATE(last_seen) < DATE_SUB(CURDATE(), INTERVAL 5 DAY);
DELETE FROM arpdata WHERE DATE(last_seen) < DATE_SUB(CURDATE(), INTERVAL 5 DAY);

# Check on daemon for any hosts offline for 1 hr

SELECT DISTINCT hostname FROM daemondata WHERE last_updated < DATE_SUB(NOW(), INTERVAL 1 HOUR);
