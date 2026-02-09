import { parseArgs } from "util";
import showHelp from "../docs/help";

const { values, positionals } = parseArgs({
    args: Bun.argv,
    options: {
        help: {
            type: "boolean",
            short: "h",
            description: "Show this help message and exit",
        },
    },
    strict: true,
    allowPositionals: true,
});

if (values.help) {
    showHelp();
    // Exit the process after showing help
    process.exit(0);
}