#!/usr/bin/env node
import { run } from "./main";

// The only module that touches the process exit code. `run()` does all the work
// and returns the code, so the logic stays testable without spawning node.
void run(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});
