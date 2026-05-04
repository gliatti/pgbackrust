/***********************************************************************************************************************************
Version Numbers and Names
***********************************************************************************************************************************/
#ifndef VERSION_H
#define VERSION_H

/***********************************************************************************************************************************
Official name of the project. PROJECT_NAME_COMPAT is the original upstream name kept for backward compatibility (config search paths,
log identifiers, etc.) until the migration is complete (Phase 212).
***********************************************************************************************************************************/
#define PROJECT_NAME                                                "pgBackRust"
#define PROJECT_NAME_COMPAT                                         "pgBackRest"

/***********************************************************************************************************************************
Standard binary name. PROJECT_BIN_COMPAT is the legacy binary name installed as a symlink alias.
***********************************************************************************************************************************/
#define PROJECT_BIN                                                 "pgbackrust"
#define PROJECT_BIN_COMPAT                                          "pgbackrest"

/***********************************************************************************************************************************
Config file name. The path will vary based on configuration.
***********************************************************************************************************************************/
#define PROJECT_CONFIG_FILE                                         PROJECT_BIN ".conf"

/***********************************************************************************************************************************
Config include path name. The parent path will vary based on configuration.
***********************************************************************************************************************************/
#define PROJECT_CONFIG_INCLUDE_PATH                                 "conf.d"

/***********************************************************************************************************************************
Format Number -- defines format for info and manifest files as well as on-disk structure. If this number changes then the repository
will be invalid unless migration functions are written.
***********************************************************************************************************************************/
#define REPOSITORY_FORMAT                                           5

/***********************************************************************************************************************************
Project version components. PROJECT_VERSION and PROJECT_VERSION_NUM are automatically generated from the component parts.
***********************************************************************************************************************************/
#define PROJECT_VERSION_MAJOR                                       2
#define PROJECT_VERSION_MINOR                                       59
#define PROJECT_VERSION_PATCH                                       0
#define PROJECT_VERSION_SUFFIX                                      "dev"

#define PROJECT_VERSION                                             "2.59.0dev"
#define PROJECT_VERSION_NUM                                         2059000

#endif
