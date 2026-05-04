/***********************************************************************************************************************************
Project Display Name and Binary Name
***********************************************************************************************************************************/
#include "build.auto.h"

#include <string.h>

#include "common/project.h"
#include "version.h"

/***********************************************************************************************************************************
Cached invocation names. Defaulted to the modern names; projectInit() flips them to the compat names if argv[0] indicates the
binary was launched through the legacy alias.
***********************************************************************************************************************************/
static const char *projectNameLocal = PROJECT_NAME;
static const char *projectBinLocal = PROJECT_BIN;

/**********************************************************************************************************************************/
void
projectInit(const char *const argv0)
{
    if (argv0 == NULL)
        return;

    // Strip any path prefix from argv[0] so we only look at the basename
    const char *base = strrchr(argv0, '/');
    base = base != NULL ? base + 1 : argv0;

    if (strcmp(base, PROJECT_BIN_COMPAT) == 0)
    {
        projectNameLocal = PROJECT_NAME_COMPAT;
        projectBinLocal = PROJECT_BIN_COMPAT;
    }
}

/**********************************************************************************************************************************/
const char *
projectName(void)
{
    return projectNameLocal;
}

/**********************************************************************************************************************************/
const char *
projectBin(void)
{
    return projectBinLocal;
}
