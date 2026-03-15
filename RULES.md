## No more than 5 EC2 instances
Do not allow creating new EC2 instances if there are already 5 or more running.
The agent should be blocked from executing any AWS EC2 run-instances or
create-instance commands when this limit is reached.

## RunPod spending limit
Block creating new RunPod pods if the current balance is below $10.
Check the RunPod balance before allowing pod creation.

## No push to main
Never allow any git push directly to main or master branch.
Block any shell command containing `git push` that targets main or master,
whether regular push, force push, or any variant.
The agent must use feature branches and create pull requests instead.

## GitHub PR limit per repo
Do not create new pull requests if a repository already has more than
10 open PRs. This prevents PR spam and encourages finishing existing work.
The repo owner/name should be extracted from the tool arguments or
git remote origin.

## No public S3 buckets
Block any AWS S3 command that sets a bucket ACL to public-read or
public-read-write. Also block put-bucket-policy commands that contain
"Principal": "*".

## No curse words
Block any user input that contains profanity, slurs, insults, or curse words
in any language including obfuscated variants. This applies to all prompts
sent to the agent. The agent should not process requests containing such language.
