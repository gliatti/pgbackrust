/***********************************************************************************************************************************
Project Display Name and Binary Name

Tracks how the binary was invoked (through argv[0]) so output that is shown to the user can adapt to the alias name
(PROJECT_BIN_COMPAT) used during the C->Rust migration. The detected name is selected once at startup by projectInit() and never
changes afterwards.
***********************************************************************************************************************************/
#ifndef COMMON_PROJECT_H
#define COMMON_PROJECT_H

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
// Resolve the invocation name from argv[0] and remember it for the rest of the process. Safe to call with NULL — defaults to
// PROJECT_NAME / PROJECT_BIN if the basename of argv[0] does not match either PROJECT_BIN or PROJECT_BIN_COMPAT.
void projectInit(const char *argv0);

// Display name of the project for user-facing output (banner, help, version, log greetings). Equals PROJECT_NAME if invoked as
// PROJECT_BIN, PROJECT_NAME_COMPAT if invoked as PROJECT_BIN_COMPAT.
const char *projectName(void);

// Binary name to suggest in user-facing usage strings. Mirrors the choice made by projectName().
const char *projectBin(void);

#endif
