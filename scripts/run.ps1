# run.ps1 — interactive enroll/verify on Fedora
# Usage:
#   .\scripts\run.ps1           # enroll
#   .\scripts\run.ps1 verify    # verify
#   .\scripts\run.ps1 list      # list enrolled prints

param([string]$Action = "enroll")
$REMOTE = "mrcook1e@192.168.1.23"
ssh -t $REMOTE "bash ~/dev/goodix-gm168/scripts/run.sh $Action"
