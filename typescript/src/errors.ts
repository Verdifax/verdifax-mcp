/** A refusal or failure a tool reports to the assistant, in plain words. */
export class ToolError extends Error {}

/** A reason this server will not start. */
export class StartupError extends Error {}
