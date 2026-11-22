package verdifaxmcp

// ToolError is a refusal or failure a tool reports to the assistant, in
// plain words.
type ToolError struct{ Message string }

func (e *ToolError) Error() string { return e.Message }

func toolErr(message string) error { return &ToolError{Message: message} }

// StartupError is a reason this server will not start.
type StartupError struct{ Message string }

func (e *StartupError) Error() string { return e.Message }

func startupErr(message string) error { return &StartupError{Message: message} }
