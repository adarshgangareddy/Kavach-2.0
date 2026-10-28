# Secrets and weak-crypto benchmark

Labelled cases for `eval/run.py`: each line ending in `# expect CWE-<n>` should be reported,
each line ending in `# decoy` looks similar but is fine and should not be. The files are only
read by the detectors, never imported or run. All values are made up; token-shaped ones are
split into two string pieces so secret scanners do not treat this folder as a leak.

Written by our team, so the numbers it gives are indicative, not a benchmark of real code.
