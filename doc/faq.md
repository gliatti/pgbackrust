# pgBackRust — Frequently Asked Questions

## Introduction

Frequently Asked Questions are intended to provide details for specific questions that may or may not be covered in the User Guide, Configuration, or Command reference. If you are unable to find details for your specific issue here, remember that the pgBackRust [Issues List in GitHub](https://github.com/gliatti/pgbackrust/issues) is also a valuable resource.

## What if I get the "could not find WAL segment" error?

The cause of this error can be a result of many different issues, some of which may be:

- misconfigured archive_command
- misconfigured pgBackRust configuration files
- network or permissions issue
- third party product (e.g. S3, Swift or Minio) configuration issue
- large amount of WAL queueing to be archived

It is advisable to:

- check the archive_command in PostgreSQL
- check the pgBackRust configuration settings on each host (e.g. pg* settings are set on the repository host and repo* settings on the pg host)
- run the `check` command with `--archive-timeout` set to a higher value than in the pgBackRust configuration file (or default) to see if the WAL queue needs more time to clear. If the system is generating a lot of WAL, then consider configuring [asynchronous archiving](user-guide.md#asynchronous-archiving)

## How do I manually purge a backup set?

A full backup set can be expired using the `--set` option of the `expire` command (see `pgbackrust help expire`).

## How can I configure options independently for each command?

pgBackRust has the ability to set options independently in the configuration file for each command. [Configure Cluster Stanza](user-guide.md#configure-cluster-stanza) details this feature as well as option precedence.

For example, the `process-max` option can be optimized for each command:

```
[global]
# used where not overridden
process-max=2

[global:backup]
# more cores for backup
process-max=4

[global:restore]
# all the cores for restore
process-max=8

[global:archive-push]
# more cores for archive-push
process-max=3

[global:archive-get]
# fewer cores for archive-get
process-max=1
```

## Can I use dots (periods) in my S3 bucket name?

RFC-2818 does not allow wildcards to match on a dot (.) so s3 bucket names must not contain dots. If there are dots in the S3 bucket name then an error such as "unable to find hostname 'my.backup.bucket.s3.amazonaws.com' in certificate common name or subject alternative names" will occur.

## Why does a backup attempt fail when `backup-standby=y` and the standby database is down?

Configuring backup from standby is generally intended to reduce load on the primary, so switching backups to the primary when the standby is down often defeats the point. Putting more load on the primary in a situation where there are already failures in the system is not recommended. Backups are not critical as long as you have one that is fairly recent -- the important thing is to keep up with WAL archiving. There is plenty of time to get a backup when the system is stable again.

If you really need a backup, the solution is to have more standbys or remove `backup-standby`. This can be overridden on the command line with `--no-backup-standby`, so there is no need to reconfigure for a one-off backup.

## Should I setup my repository on a standby host?

No. When primary and standby databases are configured, the pgBackRust configuration files should be symmetric in order to seamlessly handle failovers. If they are not, the configurations will need to be changed on failover or further problems may result.

See the [Dedicated Repository Host](user-guide.md#dedicated-repository-host) section of the User Guide for more information.

## Time-based Point-in-Time Recovery does not appear to work, why?

The most common mistake when using time-based Point-in-Time Recovery is forgetting to choose a backup set that is before the target time. pgBackRust will attempt to discover a backup to play forward from the time specified by the `--target=` if the `--set` option is not specified. If a backup set cannot be found, then restore will default to the latest backup. However, if the latest backup is after the target time, then `--target=` is not considered valid by PostgreSQL and is therefore ignored, resulting in WAL recovery to the latest time available.

To use the `--set` option, choose a backup set by running the `info` command and finding the backup with a timestamp stop that is before the target time. Then when running the restore, specify the option `--set=BACKUP_LABEL` where `BACKUP_LABEL` is the chosen backup set.

See the [Point-in-Time Recovery](user-guide.md#point-in-time-recovery) section of the User Guide for more information.

## What does the WAL archive suffix mean?

The suffix is the SHA1 checksum used to verify file integrity. There is no way to omit it.

## Does it take longer to restore specific backup types (full, differential, incremental)?

The various backup types require the same amount of time to restore. Restore retrieves files based on the backup manifest, which may reference files from a previous backup in the case of incremental or differential backups. While there could be differences in time spent *making* a given backup (depending on backup type), database size determines restore time (disk I/O, network I/O, etc. being equal).

## How can I export a backup for use in a network-isolated environment?

pgBackRust uses the repository not only to store backups and WAL archives but also to maintain essential metadata required for features such as compression, encryption, and file bundling. Because of this, simply copying a backup along with a subset of WAL files usually will not work unless very specific and restrictive conditions are met.

However, there is a workaround if your goal is to create a self-contained export of a database that you can transfer (e.g., via USB). You can make a backup with the `--archive-copy` option enabled to ensure that the necessary WAL segments are stored along with the backup. Then, restore it using `--type=none` --pg1-path=/your/target/path. This produces a restored PostgreSQL data directory with all required WAL files already placed in `pg_wal`, similar to what `pg_basebackup` would create.

You can then copy this directory to another system, and PostgreSQL should be able to recover from it without needing access to the pgBackRust repository.

Please note that recovering this backup will not result in a timeline switch, which means that this cluster should not push WAL to the original repository that it was exported from. If the new cluster is in a network-isolated environment this should not be a problem.
