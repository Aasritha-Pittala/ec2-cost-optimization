# Project 2 – Automate EC2 Cost Optimization with Lambda and EventBridge

## Overview
In this project, I automated EC2 cost optimization by creating a Lambda function that monitors CPU usage and stops idle EC2 instances. The function runs on a schedule using EventBridge, and I used an IAM role with proper permissions to manage instances securely. This project helped me understand serverless automation, CloudWatch monitoring, and IAM roles in AWS.

---

## Services and Tools Used
- Amazon EC2
- AWS Lambda
- Amazon CloudWatch
- AWS EventBridge (CloudWatch Events)
- IAM Roles and Policies
- Python (for Lambda code)

---

## What I Did

### 1. Prepared a Test EC2
I used my existing EC2 instance from Project 1 as the test target and optionally added a tag for safer automation:

Key = AutoStop
Value = true

This ensures that the Lambda only stops tagged instances. I verified the tag in the EC2 Console.

---

### 2. Created IAM Role for Lambda
I created a new IAM role with Lambda as the trusted entity. I attached the `AWSLambdaBasicExecutionRole` for CloudWatch Logs and added an inline policy allowing:

- `ec2:DescribeInstances` and `ec2:StopInstances`
- `cloudwatch:GetMetricStatistics`, `cloudwatch:ListMetrics`, `cloudwatch:GetMetricData`

This gave the Lambda permission to monitor and stop EC2 instances as needed.

---

### 3. Created the Lambda Function
I created a Lambda function named `stop-idle-ec2` with Python runtime (3.9+). I attached the IAM role I created and pasted the following code:

```python
import os
import boto3
import logging
from datetime import datetime, timedelta, timezone

log = logging.getLogger()
log.setLevel(logging.INFO)

THRESHOLD = float(os.getenv("THRESHOLD", "5"))         # percent
LOOKBACK_MINS = int(os.getenv("LOOKBACK_MINS", "60"))  # minutes
REQUIRE_TAG_KEY = os.getenv("REQUIRE_TAG_KEY", "")     # e.g., "AutoStop"
REQUIRE_TAG_VALUE = os.getenv("REQUIRE_TAG_VALUE", "") # e.g., "true"

ec2 = boto3.client("ec2")
cw = boto3.client("cloudwatch")

def instance_has_required_tag(inst):
    if not REQUIRE_TAG_KEY:
        return True
    for tag in inst.get("Tags", []):
        if tag["Key"] == REQUIRE_TAG_KEY and (REQUIRE_TAG_VALUE == "" or tag["Value"].lower() == REQUIRE_TAG_VALUE.lower()):
            return True
    return False

def get_avg_cpu(instance_id):
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=LOOKBACK_MINS)
    resp = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name":"InstanceId","Value":instance_id}],
        StartTime=start,
        EndTime=end,
        Period=300,
        Statistics=["Average"]
    )
    dps = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
    if not dps:
        return 0.0
    avg = sum(dp["Average"] for dp in dps) / len(dps)
    return avg

def lambda_handler(event, context):
    reservations = ec2.describe_instances(Filters=[{"Name":"instance-state-name","Values":["running"]}]).get("Reservations", [])
    stopped = []
    for res in reservations:
        for inst in res.get("Instances", []):
            iid = inst["InstanceId"]
            if not instance_has_required_tag(inst):
                log.info(f"Skipping {iid} (tag requirement not met)")
                continue
            avg_cpu = get_avg_cpu(iid)
            log.info(f"{iid} avg CPU over last {LOOKBACK_MINS} mins = {avg_cpu:.2f}%")
            if avg_cpu < THRESHOLD:
                log.info(f"Stopping idle instance {iid}")
                ec2.stop_instances(InstanceIds=[iid])
                stopped.append(iid)
    return {"stopped": stopped}
I also configured environment variables for the Lambda:

THRESHOLD = 5

LOOKBACK_MINS = 60

(Optional) REQUIRE_TAG_KEY = AutoStop and REQUIRE_TAG_VALUE = true for tagged instances

4. Created EventBridge Rule
I created a scheduled EventBridge rule named stop-idle-ec2-every-15m to trigger the Lambda every 15 minutes. The Lambda function was set as the target. This allowed the automation to run without manual intervention.

5. Tested and Validated
I tested the Lambda function manually using the default empty test event ({}). I checked CloudWatch Logs to see CPU readings and which instances were stopped.
Once the Lambda ran successfully, I verified in the EC2 console that idle instances with the tag were being stopped automatically.

6. Clean-Up
To avoid unnecessary charges, I deleted or disabled the EventBridge rule, deleted the Lambda function, terminated any EC2 instances that were no longer needed, and deleted the IAM role if it was not required.

Outcome
Through this project, I successfully:

Automated EC2 cost optimization using Lambda and EventBridge

Used IAM roles and inline policies to secure permissions

Monitored EC2 CPU utilization with CloudWatch

Safely stopped idle EC2 instances using tag-based filtering

