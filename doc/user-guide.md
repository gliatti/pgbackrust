# pgBackRust User Guide — Debian & Ubuntu

## Introduction

This user guide is intended to be followed sequentially from beginning to end - each section depends on the last. For example, the [Restore](#restore-1) section relies on setup that is performed in the [Quick Start](#quick-start) section. Once pgBackRust is up and running then skipping around is possible but following the user guide in order is recommended the first time through.

Although the examples in this guide are targeted at Debian/Ubuntu and PostgreSQL 17, it should be fairly easy to apply the examples to any Unix distribution and PostgreSQL version. The only OS-specific commands are those to create, start, stop, and drop PostgreSQL clusters. The pgBackRust commands will be the same on any Unix system though the location of the executable may vary. While pgBackRust strives to operate consistently across versions of PostgreSQL, there are subtle differences between versions of PostgreSQL that may show up in this guide when illustrating certain examples, e.g. PostgreSQL path/file names and settings.

Configuration information and documentation for PostgreSQL can be found in the PostgreSQL [Manual](http://www.postgresql.org/docs/17/static/index.html).

A somewhat novel approach is taken to documentation in this user guide. Each command is run on a virtual machine when the documentation is built from the XML source. This means you can have a high confidence that the commands work correctly in the order presented. Output is captured and displayed below the command when appropriate. If the output is not included it is because it was deemed not relevant or was considered a distraction from the narrative.

All commands are intended to be run as an unprivileged user that has sudo privileges for both the `root` and `postgres` users. It's also possible to run the commands directly as their respective users without modification and in that case the `sudo` commands can be stripped off.

## Concepts

The following concepts are defined as they are relevant to pgBackRust, PostgreSQL, and this user guide.

### Backup

A backup is a consistent copy of a database cluster that can be restored to recover from a hardware failure, to perform Point-In-Time Recovery, or to bring up a new standby.

**Full Backup**: pgBackRust copies the entire contents of the database cluster to the backup. The first backup of the database cluster is always a Full Backup. pgBackRust is always able to restore a full backup directly. The full backup does not depend on any files outside of the full backup for consistency.

**Differential Backup**: pgBackRust copies only those database cluster files that have changed since the last full backup. pgBackRust restores a differential backup by copying all of the files in the chosen differential backup and the appropriate unchanged files from the previous full backup. The advantage of a differential backup is that it requires less disk space than a full backup, however, the differential backup and the full backup must both be valid to restore the differential backup.

**Incremental Backup**: pgBackRust copies only those database cluster files that have changed since the last backup (which can be another incremental backup, a differential backup, or a full backup). As an incremental backup only includes those files changed since the prior backup, they are generally much smaller than full or differential backups. As with the differential backup, the incremental backup depends on other backups to be valid to restore the incremental backup. Since the incremental backup includes only those files since the last backup, all prior incremental backups back to the prior differential, the prior differential backup, and the prior full backup must all be valid to perform a restore of the incremental backup. If no differential backup exists then all prior incremental backups back to the prior full backup, which must exist, and the full backup itself must be valid to restore the incremental backup.

### Restore

A restore is the act of copying a backup to a system where it will be started as a live database cluster. A restore requires the backup files and one or more WAL segments in order to work correctly.

### Write Ahead Log (WAL)

WAL is the mechanism that PostgreSQL uses to ensure that no committed changes are lost. Transactions are written sequentially to the WAL and a transaction is considered to be committed when those writes are flushed to disk. Afterwards, a background process writes the changes into the main database cluster files (also known as the heap). In the event of a crash, the WAL is replayed to make the database consistent.

WAL is conceptually infinite but in practice is broken up into individual 16MB files called segments. WAL segments follow the naming convention `0000000100000A1E000000FE` where the first 8 hexadecimal digits represent the timeline and the next 16 digits are the logical sequence number (LSN).

### Encryption

Encryption is the process of converting data into a format that is unrecognizable unless the appropriate password (also referred to as passphrase) is provided.

pgBackRust will encrypt the repository based on a user-provided password, thereby preventing unauthorized access to data stored within the repository.

## Upgrading pgBackRust

### Upgrading pgBackRust from v2.x to v2.y

Upgrading from v2.x to v2.y is straight-forward. The repository format has not changed, so for most installations it is simply a matter of installing binaries for the new version. It is also possible to downgrade if you have not used new features that are unsupported by the older version.

> **Important:** The local and remote pgBackRust versions must match exactly so they should be upgraded together. If there is a mismatch, WAL archiving and backups will not function until the versions match. In such a case, the following error will be reported: `[ProtocolError] expected value '2.x' for greeting key 'version' but got '2.y'`.

## Build

pgBackRust is a Rust workspace built with Cargo. It is best to use a build host rather than building on production. pgBackRust consists of a single executable so it is easy to copy to a new host once it is built.

**`build`** — Install build dependencies

```
sudo apt-get install gcc pkg-config libpq-dev libssl-dev libssh2-1-dev zlib1g-dev libbz2-dev \
    liblz4-dev libzstd-dev
```

**`build`** — Compile pgBackRust

```
cargo build --workspace --release
```

The executable is written to `target/release/pgbackrust`. The repository also provides a Docker based build that does not require Rust on the host, see [README.md](../README.md).

## Installation

A new host named `pg-primary` is created to contain the demo cluster and run pgBackRust examples.

Installing pgBackRust from a package is preferable to building from source. When installing from a package the rest of the instructions in this section are generally not required, but it is possible that a package will skip creating one of the directories or apply incorrect permissions. In that case it may be necessary to manually create directories or update permissions.

If packages are not provided for your distribution/version you can [build from source](#build) and then install manually as shown here.

**`pg-primary`** — Install dependencies

```
sudo apt-get install postgresql-client libpq5 libssh2-1 zlib1g libbz2-1.0 liblz4-1 libzstd1 libssl3
```

**`pg-primary`** — Copy pgBackRust binary from build host

```
sudo scp build:pgbackrust/target/release/pgbackrust /usr/bin
sudo chmod 755 /usr/bin/pgbackrust
```

pgBackRust requires log and configuration directories and a configuration file.

**`pg-primary`** — Create pgBackRust configuration file and directories

```
sudo mkdir -p -m 770 /var/log/pgbackrust
sudo chown postgres:postgres /var/log/pgbackrust
sudo mkdir -p /etc/pgbackrust
sudo mkdir -p /etc/pgbackrust/conf.d
sudo touch /etc/pgbackrust/pgbackrust.conf
sudo chmod 640 /etc/pgbackrust/pgbackrust.conf
sudo chown postgres:postgres /etc/pgbackrust/pgbackrust.conf
```

pgBackRust should now be properly installed but it is best to check. If any dependencies were missed then you will get an error when running pgBackRust from the command line.

**`pg-primary`** — Make sure the installation worked

```
sudo -u postgres pgbackrust
```

## Quick Start

The Quick Start section will cover basic configuration of pgBackRust and PostgreSQL and introduce the `backup`, `restore`, and `info` commands.

### Setup Demo Cluster

Creating the demo cluster is optional but is strongly recommended, especially for new users, since the example commands in the user guide reference the demo cluster; the examples assume the demo cluster is running on the default port (i.e. 5432). The cluster will not be started until a later section because there is still some configuration to do.

**`pg-primary`** — Create the demo cluster

```
sudo -u postgres /usr/lib/postgresql/17/bin/initdb -D /var/lib/postgresql/17/demo -k -A peer
sudo pg_createcluster 17 demo
```

### Configure Cluster Stanza

A stanza is the configuration for a PostgreSQL database cluster that defines where it is located, how it will be backed up, archiving options, etc. Most db servers will only have one PostgreSQL database cluster and therefore one stanza, whereas backup servers will have a stanza for every database cluster that needs to be backed up.

It is tempting to name the stanza after the primary cluster but a better name describes the databases contained in the cluster. Because the stanza name will be used for the primary and all replicas it is more appropriate to choose a name that describes the actual function of the cluster, such as app or dw, rather than the local cluster name, such as main or prod.

The name 'demo' describes the purpose of this cluster accurately so that will also make a good stanza name.

pgBackRust needs to know where the base data directory for the PostgreSQL cluster is located. The path can be requested from PostgreSQL directly but in a recovery scenario the PostgreSQL process will not be available. During backups the value supplied to pgBackRust will be compared against the path that PostgreSQL is running on and they must be equal or the backup will return an error. Make sure that `pg-path` is exactly equal to `data_directory` as reported by PostgreSQL.

By default Debian/Ubuntu stores clusters in `/var/lib/postgresql/[version]/[cluster]` so it is easy to determine the correct path for the data directory.

When creating the `/etc/pgbackrust/pgbackrust.conf` file, the database owner (usually `postgres`) must be granted read privileges.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure the PostgreSQL cluster data directory

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
```

pgBackRust configuration files follow a Windows INI-like convention. Sections are denoted by text in brackets and key/value pairs are contained in each section. Lines beginning with `#` are ignored and can be used as comments. Quoting is not supported and whitespace is trimmed from keys and values. Sections will be merged if they appear more than once.

There are multiple ways the pgBackRust configuration files can be loaded:

- `config` and `config-include-path` are default: the default config file will be loaded, if it exists, and `*.conf` files in the default config include path will be appended, if they exist.
- `config` option is specified: only the specified config file will be loaded and is expected to exist.
- `config-include-path` is specified: `*.conf` files in the config include path will be loaded and the path is required to exist. The default config file will be be loaded if it exists. If it is desirable to load only the files in the specified config include path, then the `--no-config` option can also be passed.
- `config` and `config-include-path` are specified: using the user-specified values, the config file will be loaded and `*.conf` files in the config include path will be appended. The files are expected to exist.
- `config-path` is specified: this setting will override the base path for the default location of the config file and/or the base path of the default config-include-path setting unless the config and/or config-include-path option is explicitly set.

Files are concatenated as if they were one big file and each file must be valid individually. This means sections must be specified in each file where they are needed to store a key/value. Order doesn't matter but there is precedence based on sections. The precedence (highest to lowest) is:

- [*stanza*:*command*]
- [*stanza*]
- [global:*command*]
- [global]

> **Note:** `--config`, `--config-include-path` and `--config-path` are command-line only options.

pgBackRust can also be configured using environment variables as described in the command reference.

**`pg-primary`** — Configure `log-path` using the environment

```
sudo -u postgres bash -c ' export PGBACKRUST_LOG_PATH=/path/set/by/env && pgbackrust --log-level-console=error \
    help backup log-path'
```

### Create the Repository

The repository is where pgBackRust stores backups and archives WAL segments.

It may be difficult to estimate in advance how much space you'll need. The best thing to do is take some backups then record the size of different types of backups (full/incr/diff) and measure the amount of WAL generated per day. This will give you a general idea of how much space you'll need, though of course requirements will likely change over time as your database evolves.

For this demonstration the repository will be stored on the same host as the PostgreSQL server. This is the simplest configuration and is useful in cases where traditional backup software is employed to backup the database host.

**`pg-primary`** — Create the pgBackRust repository

```
sudo mkdir -p /var/lib/pgbackrust
sudo chmod 750 /var/lib/pgbackrust
sudo chown postgres:postgres /var/lib/pgbackrust
```

The repository path must be configured so pgBackRust knows where to find it.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure the pgBackRust repository path

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-path=/var/lib/pgbackrust
```

Multiple repositories may also be configured. See [Multiple Repositories](#multiple-repositories) for details.

### Configure Archiving

Backing up a running PostgreSQL cluster requires WAL archiving to be enabled. `%p` is how PostgreSQL specifies the location of the WAL segment to be archived. Note that *at least* one WAL segment will be created during the backup process even if no explicit writes are made to the cluster.

**`pg-primary`:`/etc/postgresql/17/demo/postgresql.conf`** — Configure archive settings

```ini
archive_command = 'pgbackrust --stanza=demo archive-push %p'
archive_mode = on
```

The PostgreSQL cluster must be restarted after making these changes and before performing a backup.

**`pg-primary`** — Restart the demo cluster

```
sudo pg_ctlcluster 17 demo restart
```

When archiving a WAL segment is expected to take more than 60 seconds (the default) to reach the pgBackRust repository, then the pgBackRust `archive-timeout` option should be increased. Note that this option is not the same as the PostgreSQL `archive_timeout` option which is used to force a WAL segment switch; useful for databases where there are long periods of inactivity. For more information on the PostgreSQL `archive_timeout` option, see PostgreSQL [Write Ahead Log](https://www.postgresql.org/docs/current/static/runtime-config-wal.html).

The `archive-push` command can be configured with its own options. For example, a lower compression level may be set to speed archiving without affecting the compression used for backups.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Config `archive-push` to use a lower compression level

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-path=/var/lib/pgbackrust

[global:archive-push]
compress-level=3
```

This configuration technique can be used for any command and can even target a specific stanza, e.g. `demo:archive-push`.

### Configure Retention

pgBackRust expires backups based on retention options.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure retention to 2 full backups

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2

[global:archive-push]
compress-level=3
```

More information about retention can be found in the [Retention](#retention) section.

### Configure Repository Encryption

The repository will be configured with a cipher type and key to demonstrate encryption. Encryption is always performed client-side even if the repository type (e.g. S3 or other object store) supports encryption.

It is important to use a long, random passphrase for the cipher key. A good way to generate one is to run: `openssl rand -base64 48`.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure pgBackRust repository encryption

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2

[global:archive-push]
compress-level=3
```

Once the repository has been configured and the stanza created and checked, the repository encryption settings cannot be changed.

### Create the Stanza

The `stanza-create` command must be run to initialize the stanza. It is recommended that the `check` command be run after `stanza-create` to ensure archiving and backups are properly configured.

**`pg-primary`** — Create the stanza and check the configuration

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info stanza-create
```

### Check the Configuration

The `check` command validates that pgBackRust and the `archive_command` setting are configured correctly for archiving and backups for the specified stanza. It will attempt to check all repositories and databases that are configured for the host on which the command is run. It detects misconfigurations, particularly in archiving, that result in incomplete backups because required WAL segments did not reach the archive. The command can be run on the PostgreSQL or repository host. The command may also be run on the standby host, however, since `pg_switch_xlog()`/`pg_switch_wal()` cannot be performed on the standby, the command will only test the repository configuration.

Note that `pg_create_restore_point('pgBackRust Archive Check')` and `pg_switch_xlog()`/`pg_switch_wal()` are called to force PostgreSQL to archive a WAL segment.

**`pg-primary`** — Check the configuration

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info check
```

### Performance Tuning

pgBackRust has a number of performance options that are not enabled by default to maintain backward compatibility in the repository. However, when creating a new repository the following options are recommended. They can also be used on an existing repository with the caveat that older versions of pgBackRust will not be able to read the repository. This incompatibility depends on when the feature was introduced, as noted in the list below.

- `compress-type` - determines the compression algorithm used by the `backup` and `archive-push` commands. The default is `gz` (Gzip) but `zst` (Zstandard) is recommended because it is much faster and provides compression similar to `gz`. `zst` has been supported by the `compress-type` option since v2.27. See Compress Type for more details.
- `repo-bundle` - combines small files during backup to save space and improve the speed of both the `backup` and `restore` commands, especially on object stores such as S3. The `repo-bundle` option was introduced in v2.39. See [File Bundling](#file-bundling) for more details.
- `repo-block` - stores only the portions of files that have changed rather than the entire file during `diff`/`incr` `backup`. This saves space and increases the speed of the `backup`. The `repo-block` option was introduced in v2.46 but at least v2.52.1 is recommended. See [Block Incremental](#block-incremental) for more details.

There are other performance options that are not enabled by default because they require additional configuration or because the default is safe (but not optimal). These options are available in all v2 versions of pgBackRust.

- `process-max` - determines how many processes will be used for commands. The default is 1, which is almost never the appropriate value. Each command uses `process-max` differently so refer to each command's documentation for details on usage.
- `archive-async` - archives WAL files to the repository in batch which greatly increases archiving speed. It is not enabled by default because it requires a spool path to be created. See [Asynchronous Archiving](#asynchronous-archiving) for more details.
- `backup-standby` - performs the backup on a standby rather than the primary to reduce load on the primary. It is not enabled by default because it requires additional configuration and the presence of one or more standby hosts. See [Backup from a Standby](#backup-from-a-standby) for more details.

### Perform a Backup

By default pgBackRust will wait for the next regularly scheduled checkpoint before starting a backup. Depending on the `checkpoint_timeout` and `checkpoint_segments` settings in PostgreSQL it may be quite some time before a checkpoint completes and the backup can begin. Generally, it is best to set `start-fast=y` so that the backup starts immediately. This forces a checkpoint, but since backups are usually run once a day an additional checkpoint should not have a noticeable impact on performance. However, on very busy clusters it may be best to pass `--start-fast` on the command-line as needed.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure backup fast start

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y

[global:archive-push]
compress-level=3
```

To perform a backup of the PostgreSQL cluster run pgBackRust with the `backup` command.

**`pg-primary`** — Backup the demo cluster

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info backup
```

By default pgBackRust performs a full backup. A differential or incremental backup must be based on a prior backup, so when none exists pgBackRust runs a full backup instead.

The `type` option can be used to specify a full or differential backup.

**`pg-primary`** — Differential backup of the demo cluster

```
sudo -u postgres pgbackrust --stanza=demo --type=diff --log-level-console=info backup
```

While incremental backups can be based on a full *or* differential backup, differential backups must be based on a full backup. A full backup can be performed by running the `backup` command with `--type=full`.

During an online backup pgBackRust waits for WAL segments that are required for backup consistency to be archived. This wait time is governed by the pgBackRust `archive-timeout` option which defaults to 60 seconds. If archiving an individual segment is known to take longer then this option should be increased.

### Schedule a Backup

Backups can be scheduled with utilities such as cron.

In the following example, two cron jobs are configured to run; full backups are scheduled for 6:30 AM every Sunday with differential backups scheduled for 6:30 AM Monday through Saturday. If this crontab is installed for the first time mid-week, then pgBackRust will run a full backup the first time the differential job is executed, followed the next day by a differential backup.

```
#m h   dom mon dow   command
30 06  *   *   0     pgbackrust --type=full --stanza=demo backup
30 06  *   *   1-6   pgbackrust --type=diff --stanza=demo backup
```

Once backups are scheduled it's important to configure retention so backups are expired on a regular schedule, see [Retention](#retention).

### Backup Information

Use the `info` command to get information about backups.

**`pg-primary`** — Get info for the demo cluster

```
sudo -u postgres pgbackrust info
```

The `info` command operates on a single stanza or all stanzas. Text output is the default and gives a human-readable summary of backups for the stanza(s) requested. This format is subject to change with any release.

For machine-readable output use `--output=json`. The JSON output contains far more information than the text output and is kept stable unless a bug is found.

To speed up execution, limit the output to only progress information by specifying `--detail-level=progress`. Note that this skips all checks except for availability of the stanza.

Each stanza has a separate section and it is possible to limit output to a single stanza with the `--stanza` option. The stanza '`status`' gives a brief indication of the stanza's health. If this is '`ok`' then pgBackRust is functioning normally. If there are multiple repositories, then a status of '`mixed`' indicates that the stanza is not in a healthy state on one or more of the repositories; in this case the state of the stanza will be detailed per repository. For cases in which an error on a repository occurred that is not one of the known error codes, then an error code of '`other`' will be used and the full error details will be provided. The '`wal archive min/max`' shows the minimum and maximum WAL currently stored in the archive and, in the case of multiple repositories, will be reported across all repositories unless the `--repo` option is set. Note that there may be gaps due to archive retention policies or other reasons.

The '`backup/expire running`' and/or '`restore running`' messages will appear beside the '`status`' information if any of those commands are currently running on the host. Per-repo progress will be also reported in text output and a '`repo`' array will be included in JSON output.

The backups are displayed oldest to newest. The oldest backup will *always* be a full backup (indicated by an `F` at the end of the label) but the newest backup can be full, differential (ends with `D`), or incremental (ends with `I`).

The '`timestamp start/stop`' defines the time period when the backup ran. The '`timestamp stop`' can be used to determine the backup to use when performing Point-In-Time Recovery. More information about Point-In-Time Recovery can be found in the [Point-In-Time Recovery](user-guide.md#point-in-time-recovery) section.

The '`wal start/stop`' defines the WAL range that is required to make the database consistent when restoring. The `backup` command will ensure that this WAL range is in the archive before completing.

The '`database size`' is the full uncompressed size of the database while '`database backup size`' is the amount of data in the database to actually back up (these will be the same for full backups).

The '`repo`' indicates in which repository this backup resides. The '`backup set size`' includes all the files from this backup and any referenced backups in the repository that are required to restore the database from this backup while '`backup size`' includes only the files in this backup (these will also be the same for full backups). Repository sizes reflect compressed file sizes if compression is enabled in pgBackRust.

The '`backup reference total`' summarizes the list of additional backups that are required to restore this backup. Use the `--set` option to display the complete reference list.

### Restore a Backup

Backups can protect you from a number of disaster scenarios, the most common of which are hardware failure and data corruption. The easiest way to simulate data corruption is to remove an important PostgreSQL cluster file.

**`pg-primary`** — Stop the demo cluster and delete the `pg_control` file

```
sudo pg_ctlcluster 17 demo stop
sudo -u postgres rm /var/lib/postgresql/17/demo/global/pg_control
```

Starting the cluster without this important file will result in an error.

**`pg-primary`** — Attempt to start the corrupted demo cluster

```
sudo pg_ctlcluster 17 demo start
```

To restore a backup of the PostgreSQL cluster run pgBackRust with the `restore` command. The cluster needs to be stopped (in this case it is already stopped) and all files must be removed from the PostgreSQL data directory.

**`pg-primary`** — Remove old files from demo cluster

```
sudo -u postgres find /var/lib/postgresql/17/demo -mindepth 1 -delete
```

**`pg-primary`** — Restore the demo cluster and start PostgreSQL

```
sudo -u postgres pgbackrust --stanza=demo restore
sudo pg_ctlcluster 17 demo start
```

This time the cluster started successfully since the restore replaced the missing `pg_control` file.

More information about the `restore` command can be found in the [Restore](#restore-1) section.

## Monitoring

Monitoring is an important part of any production system. There are many tools available and pgBackRust can be monitored on any of them with a little work.

pgBackRust can output information about the repository in JSON format which includes a list of all backups for each stanza and WAL archive info.

### In PostgreSQL

The PostgreSQL `COPY` command allows pgBackRust info to be loaded into a table. The following example wraps that logic in a function that can be used to perform real-time queries.

**`pg-primary`** — Load pgBackRust info function for PostgreSQL

```
sudo -u postgres cat /var/lib/postgresql/pgbackrust/doc/example/pgsql-pgbackrust-info.sql
sudo -u postgres psql -f /var/lib/postgresql/pgbackrust/doc/example/pgsql-pgbackrust-info.sql
```

Now the `monitor.pgbackrust_info()` function can be used to determine the last successful backup time and archived WAL for a stanza.

**`pg-primary`** — Query last successful backup time and archived WAL

```
sudo -u postgres cat /var/lib/postgresql/pgbackrust/doc/example/pgsql-pgbackrust-query.sql
sudo -u postgres psql -f /var/lib/postgresql/pgbackrust/doc/example/pgsql-pgbackrust-query.sql
```

### Using jq

jq is a command-line utility that can easily extract data from JSON.

**`pg-primary`** — Install jq utility

```
sudo apt-get install jq
```

Now jq can be used to query the last successful backup time for a stanza.

**`pg-primary`** — Query last successful backup time

```
sudo -u postgres pgbackrust --output=json --stanza=demo info | jq '.[0] | .backup[-1] | .timestamp.stop'
```

Or the last archived WAL.

**`pg-primary`** — Query last archived WAL

```
sudo -u postgres pgbackrust --output=json --stanza=demo info | jq '.[0] | .archive[-1] | .max'
```

> **Note:** This syntax requires jq v1.5.

> **Note:** jq may round large numbers such as system identifiers. Test your queries carefully.

## Backup

When multiple repositories are configured, pgBackRust will backup to the highest priority repository (e.g. `repo1`) unless the `--repo` option is specified.

pgBackRust does not have a built-in scheduler so it's best to run it from cron or some other scheduling mechanism.

See [Perform a Backup](user-guide.md#perform-a-backup) for more details and examples.

### File Bundling

Bundling files together in the repository saves time during the backup and some space in the repository. This is especially pronounced when the repository is stored on an object store such as S3 or file systems with large block sizes. Per-file creation time on object stores is higher and very small files might cost as much to store as larger files.

The file bundling feature is enabled with the `repo-bundle` option.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `repo1-bundle`

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y

[global:archive-push]
compress-level=3
```

A full backup without file bundling will have 1000+ files in the backup path, but with bundling the total number of files is greatly reduced. An additional benefit is that zero-length files are not stored (except in the manifest), whereas in a normal backup each zero-length file is stored individually.

**`pg-primary`** — Perform a full backup

```
sudo -u postgres pgbackrust --stanza=demo --type=full backup
```

**`pg-primary`** — Check file total

```
sudo -u postgres find /var/lib/pgbackrust/backup/demo/latest/ -type f | wc -l
```

The `repo-bundle-size` and `repo-bundle-limit` options can be used for tuning, though the defaults should be optimal in most cases.

While file bundling is generally more efficient, the downside is that it is more difficult to manually retrieve files from the repository. It may not be ideal for deduplicated storage since each full backup will arrange files in the bundles differently. Lastly, file bundles cannot be resumed, so be careful not to set `repo-bundle-limit` too high.

### Block Incremental

Block incremental backups save space by only storing the parts of a file that have changed since the prior backup rather than storing the entire file.

The block incremental feature is enabled with the `repo-block` option and it works best when enabled for all backup types. File bundling must also be enabled.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `repo1-block`

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y

[global:archive-push]
compress-level=3
```

### Backup Annotations

Users can attach informative key/value pairs to the backup. This option may be used multiple times to attach multiple annotations.

**`pg-primary`** — Perform a full backup with annotations

```
sudo -u postgres pgbackrust --stanza=demo --annotation=source="demo backup" --annotation=key=value --type=full backup
```

Annotations are output by the `info` command text output when a backup is specified with `--set` and always appear in the JSON output.

**`pg-primary`** — Get info for the demo cluster

```
sudo -u postgres pgbackrust --stanza=demo --set=<backup-label> info
```

Annotations included with the `backup` command can be added, modified, or removed afterwards using the `annotate` command.

**`pg-primary`** — Change backup annotations

```
sudo -u postgres pgbackrust --stanza=demo --set=<backup-label> --annotation=key= --annotation=new_key=new_value \
    annotate
sudo -u postgres pgbackrust --stanza=demo --set=<backup-label> info
```

## Retention

Generally it is best to retain as many backups as possible to provide a greater window for [Point-in-Time Recovery](#point-in-time-recovery), but practical concerns such as disk space must also be considered. Retention options remove older backups once they are no longer needed.

pgBackRust does full backup rotation based on the retention type which can be a count or a time period. When a count is specified, then expiration is not concerned with when the backups were created but with how many must be retained. Differential backups are count-based but will always be expired when the full backup they depend on is expired. Incremental backups are not expired by retention independently - they are always expired with their related full or differential backup. See sections [Full Backup Retention](user-guide.md#full-backup-retention) and [Differential Backup Retention](user-guide.md#differential-backup-retention) for details and examples.

Archived WAL is retained by default for backups that have not expired, however, although not recommended, this schedule can be modified per repository with the retention-archive options. See section [Archive Retention](user-guide.md#archive-retention) for details and examples.

The `expire` command is run automatically after each successful backup and can also be run by the user. When run by the user, expiration will occur as defined by the retention settings for each configured repository. If the `--repo` option is provided, expiration will occur only on the specified repository. Expiration can also be limited by the user to a specific backup set with the `--set` option and, unless the `--repo` option is specified, all repositories will be searched and any matching the set criteria will be expired. It should be noted that the archive retention schedule will be checked and performed any time the `expire` command is run.

### Full Backup Retention

The `repo1-retention-full-type` determines how the option `repo1-retention-full` is interpreted; either as the count of full backups to be retained or how many days to retain full backups. New backups must be completed before expiration will occur - that means if `repo1-retention-full-type=count` and `repo1-retention-full=2` then there will be three full backups stored before the oldest one is expired, or if `repo1-retention-full-type=time` and `repo1-retention-full=20` then there must be one full backup that is at least 20 days old before expiration can occur.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `repo1-retention-full`

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y

[global:archive-push]
compress-level=3
```

Backup `repo1-retention-full=2` but currently there is only one full backup so the next full backup to run will not expire any full backups.

**`pg-primary`** — Perform a full backup

```
sudo -u postgres pgbackrust --stanza=demo --type=full --log-level-console=detail backup
```

Archive *is* expired because WAL segments were generated before the oldest backup. These are not useful for recovery - only WAL segments generated after a backup can be used to recover that backup.

**`pg-primary`** — Perform a full backup

```
sudo -u postgres pgbackrust --stanza=demo --type=full --log-level-console=info backup
```

The `<first-full-backup>` full backup is expired and archive retention is based on the `<second-full-backup>` which is now the oldest full backup.

### Differential Backup Retention

Set `repo1-retention-diff` to the number of differential backups required. Differentials only rely on the prior full backup so it is possible to create a "rolling" set of differentials for the last day or more. This allows quick restores to recent points-in-time but reduces overall space consumption.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `repo1-retention-diff`

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-diff=1
repo1-retention-full=2
start-fast=y

[global:archive-push]
compress-level=3
```

Backup `repo1-retention-diff=1` so two differentials will need to be performed before one is expired. An incremental backup is added to demonstrate incremental expiration, which in this case depends on the differential expiration.

**`pg-primary`** — Perform differential and incremental backups

```
sudo -u postgres pgbackrust --stanza=demo --type=diff backup
sudo -u postgres pgbackrust --stanza=demo --type=incr backup
```

Now performing a differential backup will expire the previous differential and incremental backups leaving only one differential backup.

**`pg-primary`** — Perform a differential backup

```
sudo -u postgres pgbackrust --stanza=demo --type=diff --log-level-console=info backup
```

### Archive Retention

Although pgBackRust automatically removes archived WAL segments when expiring backups (the default expires WAL for full backups based on the `repo1-retention-full` option), it may be useful to expire archive more aggressively to save disk space. Note that full backups are treated as differential backups for the purpose of differential archive retention.

Expiring archive will never remove WAL segments that are required to make a backup consistent. However, since Point-in-Time-Recovery (PITR) only works on a continuous WAL stream, care should be taken when aggressively expiring archive outside of the normal backup expiration process. To determine what will be expired without actually expiring anything, the `dry-run` option can be provided on the command line with the `expire` command.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `repo1-retention-diff`

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-diff=2
repo1-retention-full=2
start-fast=y

[global:archive-push]
compress-level=3
```

**`pg-primary`** — Perform differential backup

```
sudo -u postgres pgbackrust --stanza=demo --type=diff --log-level-console=info backup
```

**`pg-primary`** — Expire archive

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=detail --repo1-retention-archive-type=diff \
    --repo1-retention-archive=1 expire
```

The `<first-diff-backup>` differential backup has archived WAL segments that must be retained to make the older backups consistent even though they cannot be played any further forward with PITR. WAL segments generated after `<first-diff-backup>` but before `<second-diff-backup>` are removed. WAL segments generated after the new backup `<second-diff-backup>` remain and can be used for PITR.

Since full backups are considered differential backups for the purpose of differential archive retention, if a full backup is now performed with the same settings, only the archive for that full backup is retained for PITR.

## Restore

The restore command automatically defaults to selecting the latest backup from the first repository where backups exist (see [Quick Start - Restore a Backup](user-guide.md#restore-a-backup)). The order in which the repositories are checked is dictated by the `pgbackrust.conf` (e.g. repo1 will be checked before repo2). To select from a specific repository, the `--repo` option can be passed (e.g. `--repo=1`). The `--set` option can be passed if a backup other than the latest is desired.

When PITR of `--type=time` or `--type=lsn` is specified, then the target time or target lsn must be specified with the `--target` option. If a backup is not specified via the `--set` option, then the configured repositories will be checked, in order, for a backup that contains the requested time or lsn. If no matching backup is found, the latest backup from the first repository containing backups will be used for `--type=time` while no backup will be selected for `--type=lsn`. For other types of PITR, e.g. `xid`, the `--set` option must be provided if the target is prior to the latest backup. See [Point-in-Time Recovery](user-guide.md#point-in-time-recovery) for more details and examples.

Replication slots are not included per recommendation of PostgreSQL. See [Backing Up The Data Directory](https://www.postgresql.org/docs/current/continuous-archiving.html#BACKUP-LOWLEVEL-BASE-BACKUP-DATA) in the PostgreSQL documentation for more information.

The following sections introduce additional `restore` command features.

### File Ownership

If a `restore` is run as a non-root user (the typical scenario) then all files restored will belong to the user/group executing pgBackRust. If existing files are not owned by the executing user/group then an error will result if the ownership cannot be updated to the executing user/group. In that case the file ownership will need to be updated by a privileged user before the restore can be retried.

If a `restore` is run as the `root` user then pgBackRust will attempt to recreate the ownership recorded in the manifest when the backup was made. Only user/group **names** are stored in the manifest so the same names must exist on the restore host for this to work. If the user/group name cannot be found locally then the user/group of the PostgreSQL data directory will be used and finally `root` if the data directory user/group cannot be mapped to a name.

### Delta Option

[Restore a Backup](#restore-a-backup) in [Quick Start](#quick-start) required the database cluster directory to be cleaned before the `restore` could be performed. The `delta` option allows pgBackRust to automatically determine which files in the database cluster directory can be preserved and which ones need to be restored from the backup - it also *removes* files not present in the backup manifest so it will dispose of divergent changes. This is accomplished by calculating a [SHA-1](https://en.wikipedia.org/wiki/SHA-1) cryptographic hash for each file in the database cluster directory. If the `SHA-1` hash does not match the hash stored in the backup then that file will be restored. This operation is very efficient when combined with the `process-max` option. Since the PostgreSQL server is shut down during the restore, a larger number of processes can be used than might be desirable during a backup when the PostgreSQL server is running.

**`pg-primary`** — Stop the demo cluster, perform delta restore

```
sudo pg_ctlcluster 17 demo stop
sudo -u postgres pgbackrust --stanza=demo --delta --log-level-console=detail restore
```

**`pg-primary`** — Restart PostgreSQL

```
sudo pg_ctlcluster 17 demo start
```

### Restore Selected Databases

There may be cases where it is desirable to selectively restore specific databases from a cluster backup. This could be done for performance reasons or to move selected databases to a machine that does not have enough space to restore the entire cluster backup.

To demonstrate this feature two databases are created: test1 and test2.

**`pg-primary`** — Create two test databases

```
sudo -u postgres psql -c "create database test1;"
sudo -u postgres psql -c "create database test2;"
```

Each test database will be seeded with tables and data to demonstrate that recovery works with selective restore.

**`pg-primary`** — Create a test table in each database

```
sudo -u postgres psql -c "create table test1_table (id int); insert into test1_table (id) values (1);" test1
sudo -u postgres psql -c "create table test2_table (id int); insert into test2_table (id) values (2);" test2
```

A fresh backup is run so pgBackRust is aware of the new databases.

**`pg-primary`** — Perform a backup

```
sudo -u postgres pgbackrust --stanza=demo --type=incr backup
```

One of the main reasons to use selective restore is to save space. The size of the test1 database is shown here so it can be compared with the disk utilization after a selective restore.

**`pg-primary`** — Show space used by test1 database

```
sudo -u postgres du -sh /var/lib/postgresql/17/demo/base/<test1-oid>
```

If the database to restore is not known, use the `info` command `set` option to discover databases that are part of the backup set.

**`pg-primary`** — Show database list for backup

```
sudo -u postgres pgbackrust --stanza=demo --set=<backup-label> info
```

Stop the cluster and restore only the test2 database. Built-in databases (`template0`, `template1`, and `postgres`) are always restored.

> **Warning:** Recovery may error unless `--type=immediate` is specified. This is because after consistency is reached PostgreSQL will flag zeroed pages as errors even for a full-page write. For PostgreSQL &ge; 13 the `ignore_invalid_pages` setting may be used to ignore invalid pages. In this case it is important to check the logs after recovery to ensure that no invalid pages were reported in the selected databases.

**`pg-primary`** — Restore from last backup including only the test2 database

```
sudo pg_ctlcluster 17 demo stop
sudo -u postgres pgbackrust --stanza=demo --delta --db-include=test2 --type=immediate --target-action=promote restore
sudo pg_ctlcluster 17 demo start
```

Once recovery is complete the test2 database will contain all previously created tables and data.

**`pg-primary`** — Demonstrate that the test2 database was recovered

```
sudo -u postgres psql -c "select * from test2_table;" test2
```

The test1 database, despite successful recovery, is not accessible. This is because the entire database was restored as sparse, zeroed files. PostgreSQL can successfully apply WAL on the zeroed files but the database as a whole will not be valid because key files contain no data. This is purposeful to prevent the database from being accidentally used when it might contain partial data that was applied during WAL replay.

**`pg-primary`** — Attempting to connect to the test1 database will produce an error

```
sudo -u postgres psql -c "select * from test1_table;" test1
```

Since the test1 database is restored with sparse, zeroed files it will only require as much space as the amount of WAL that is written during recovery. While the amount of WAL generated during a backup and applied during recovery can be significant it will generally be a small fraction of the total database size, especially for large databases where this feature is most likely to be useful.

It is clear that the test1 database uses far less disk space during the selective restore than it would have if the entire database had been restored.

**`pg-primary`** — Show space used by test1 database after recovery

```
sudo -u postgres du -sh /var/lib/postgresql/17/demo/base/<test1-oid>
```

At this point the only action that can be taken on the invalid test1 database is `drop database`. pgBackRust does not automatically drop the database since this cannot be done until recovery is complete and the cluster is accessible.

**`pg-primary`** — Drop the test1 database

```
sudo -u postgres psql -c "drop database test1;"
```

Now that the invalid test1 database has been dropped only the test2 and built-in databases remain.

**`pg-primary`** — List remaining databases

```
sudo -u postgres psql -c "select oid, datname from pg_database order by oid;"
```

## Point-in-Time Recovery

[Restore a Backup](#restore-a-backup) in [Quick Start](#quick-start) performed default recovery, which is to play all the way to the end of the WAL stream. In the case of a hardware failure this is usually the best choice but for data corruption scenarios (whether machine or human in origin) Point-in-Time Recovery (PITR) is often more appropriate.

Point-in-Time Recovery (PITR) allows the WAL to be played from a backup to a specified lsn, time, transaction id, or recovery point. For common recovery scenarios time-based recovery is arguably the most useful. A typical recovery scenario is to restore a table that was accidentally dropped or data that was accidentally deleted. Recovering a dropped table is more dramatic so that's the example given here but deleted data would be recovered in exactly the same way.

**`pg-primary`** — Create a table with very important data

```
sudo -u postgres psql -c "begin; create table important_table (message text); insert into important_table values \
    ('Important Data'); commit; select * from important_table;"
```

It is important to represent the time as reckoned by PostgreSQL and to include timezone offsets. This reduces the possibility of unintended timezone conversions and an unexpected recovery result.

**`pg-primary`** — Get the time from PostgreSQL

```
sudo -u postgres psql -Atc "select current_timestamp"
```

Now that the time has been recorded the table is dropped. In practice finding the exact time that the table was dropped is a lot harder than in this example. It may not be possible to find the exact time, but some forensic work should be able to get you close.

**`pg-primary`** — Drop the important table

```
sudo -u postgres psql -c "begin; drop table important_table; commit; select * from important_table;"
```

If the wrong backup is selected for restore then recovery to the required time target will fail. To demonstrate this a new incremental backup is performed where `important_table` does not exist.

**`pg-primary`** — Perform an incremental backup

```
sudo -u postgres pgbackrust --stanza=demo --type=incr backup
sudo -u postgres pgbackrust info
```

It will not be possible to recover the lost table from this backup since PostgreSQL can only play forward, not backward.

**`pg-primary`** — Attempt recovery from an incorrect backup

```
sudo pg_ctlcluster 17 demo stop
sudo -u postgres pgbackrust --stanza=demo --delta --set=<backup-label> --target-timeline=current --type=time \
    "--target=<recovery-time>" --target-action=promote restore
sudo pg_ctlcluster 17 demo start
```

A reliable method is to allow pgBackRust to automatically select a backup capable of recovery to the time target, i.e. a backup that ended before the specified time.

> **Note:** pgBackRust cannot automatically select a backup when the restore type is `xid` or `name`.

**`pg-primary`** — Restore the demo cluster to `<recovery-time>`

```
sudo -u postgres pgbackrust --stanza=demo --delta --type=time "--target=<recovery-time>" --target-action=promote \
    restore
sudo -u postgres cat /var/lib/postgresql/17/demo/postgresql.auto.conf
```

pgBackRust has generated the recovery settings in `postgresql.auto.conf` so PostgreSQL can be started immediately. `%f` is how PostgreSQL specifies the WAL segment it needs and `%p` is the location where it should be copied. Once PostgreSQL has finished recovery the table will exist again and can be queried.

**`pg-primary`** — Start PostgreSQL and check that the important table exists

```
sudo pg_ctlcluster 17 demo start
sudo -u postgres psql -c "select * from important_table"
```

The PostgreSQL log also contains valuable information. It will indicate the time and transaction where the recovery stopped and also give the time of the last transaction to be applied.

**`pg-primary`** — Examine the PostgreSQL log output

```
sudo -u postgres cat /var/log/postgresql/postgresql-17-demo.log
```

## Delete a Stanza

The `stanza-delete` command removes data in the repository associated with a stanza.

To delete a stanza:

Once the command successfully completes, it is the responsibility of the user to remove the stanza from all pgBackRust configuration files and/or environment variables.

A stanza may only be deleted from one repository at a time. To delete the stanza from multiple repositories, repeat the `stanza-delete` command for each repository while specifying the `--repo` option.

**`pg-primary`** — Stop PostgreSQL cluster to be removed

```
sudo pg_ctlcluster 17 demo stop
```

**`pg-primary`** — Stop pgBackRust for the stanza

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info stop
```

**`pg-primary`** — Delete the stanza from one repository

```
sudo -u postgres pgbackrust --stanza=demo --repo=1 --log-level-console=info stanza-delete
```

## Multiple Repositories

Multiple repositories may be configured as demonstrated in [S3 Support](#s3-compatible-object-store-support). A potential benefit is the ability to have a local repository for fast restores and a remote repository for redundancy.

Some commands, e.g. `stanza-create`/`stanza-upgrade`, will automatically work with all configured repositories while others, e.g. [stanza-delete](#delete-a-stanza), will require a repository to be specified using the `repo` option. See the command reference for details on which commands require the repository to be specified.

Note that the `repo` option is not required when only `repo1` is configured in order to maintain backward compatibility. However, the `repo` option *is* required when a single repo is configured as, e.g. `repo2`. This is to prevent command breakage if a new repository is added later.

The `archive-push` command will always push WAL to the archive in all configured repositories. When a repository cannot be reached, WAL will still be pushed to other repositories. However, for this to work effectively, `archive-async=y` must be enabled; otherwise, the other repositories can only get one WAL segment ahead of the unreachable repository. Also, note that if WAL cannot be pushed to any repository, then PostgreSQL will not remove it from the `pg_wal` directory, which may cause the volume to run out of space.

Backups can be scheduled individually for each repository, which is desirable when backup types and retention vary by repository, or taken once and mirrored to the other repositories as described in [Synchronizing Repositories](#synchronizing-repositories). Likewise, restores must specify a repository. It is generally better to specify a repository for restores that has low latency/cost even if that means more recovery time. Only restore testing can determine which repository will be most efficient.

### Synchronizing Repositories

Instead of running a backup against each repository, a backup taken in one repository can be mirrored to the others with the `repo-sync` command. It copies backups and archived WAL from the active repository (the highest priority repository, or the one given by `--repo`) to every other configured repository.

Repositories in a set are byte-identical mirrors, so the sync is a raw byte copy of the stored objects with no recompression, re-encryption, or re-bundling. This requires the repositories to share the same compression, bundling (`repo-bundle`), block incremental (`repo-block`) and cipher type settings. For encrypted repositories, the first sync to an empty repository aligns its cipher sub-key with the source.

The command is idempotent: objects already present in a destination repository are skipped, and the ancestors of a differential or incremental backup are synced first so dependency chains are never broken.

**`pg-primary`** — Mirror backups and WAL from `repo1` to the other repositories

```
sudo -u postgres pgbackrust --stanza=demo --repo=1 repo-sync
```

The `type` option limits what is synced: `all` (the default), `wal` for archived WAL only, or `backup` for backups only.

**`pg-primary`** — Mirror backups only

```
sudo -u postgres pgbackrust --stanza=demo --repo=1 --type=backup repo-sync
```

The sync can also be performed as part of the backup. When `repo-sync` is enabled for the `backup` command, the backup just written to the active repository is mirrored to every other configured repository immediately after a successful backup.

**`pg-primary`** — Backup to `repo1` and mirror the backup to the other repositories

```
sudo -u postgres pgbackrust --stanza=demo --repo=1 --repo-sync backup
```

A mirrored repository can then be used for restores with `--repo`, like any other repository.

## Azure-Compatible Object Store Support

pgBackRust supports locating repositories in Azure-compatible object stores. The container used to store the repository must be created in advance - pgBackRust will not do it automatically. The repository can be located in the container root (`/`) but it's usually best to place it in a subpath so object store logs or other data can also be stored in the container without conflicts.

> **Warning:** Do not enable "hierarchical namespace" as this will cause errors during expire.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure Azure

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-diff=2
repo1-retention-full=2
repo2-azure-account=pgbackrust
repo2-azure-container=demo-container
repo2-azure-key=YXpLZXk=
repo2-path=/demo-repo
repo2-retention-full=4
repo2-type=azure
start-fast=y

[global:archive-push]
compress-level=3
```

Shared access signatures may be used by setting the `repo2-azure-key-type` option to `sas` and the `repo2-azure-key` option to the shared access signature token.

Commands are run exactly as if the repository were stored on a local disk.

**`pg-primary`** — Create the stanza

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info stanza-create
```

File creation time in Azure is relatively slow so `backup`/`restore` performance is improved by enabling [file bundling](#file-bundling).

**`pg-primary`** — Backup the demo cluster

```
sudo -u postgres pgbackrust --stanza=demo --repo=2 --log-level-console=info backup
```

## S3-Compatible Object Store Support

pgBackRust supports locating repositories in S3-compatible object stores. The bucket used to store the repository must be created in advance - pgBackRust will not do it automatically. The repository can be located in the bucket root (`/`) but it's usually best to place it in a subpath so object store logs or other data can also be stored in the bucket without conflicts.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure S3

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-diff=2
repo1-retention-full=2
repo2-azure-account=pgbackrust
repo2-azure-container=demo-container
repo2-azure-key=YXpLZXk=
repo2-path=/demo-repo
repo2-retention-full=4
repo2-type=azure
repo3-path=/demo-repo
repo3-retention-full=4
repo3-s3-bucket=demo-bucket
repo3-s3-endpoint=s3.us-east-1.amazonaws.com
repo3-s3-key=accessKey1
repo3-s3-key-secret=verySecretKey1
repo3-s3-region=us-east-1
repo3-type=s3
start-fast=y

[global:archive-push]
compress-level=3
```

> **Note:** The region and endpoint will need to be configured to where the bucket is located. The values given here are for the `us-east-1` region.

A role should be created to run pgBackRust and the bucket permissions should be set as restrictively as possible. If the role is associated with an instance in AWS then pgBackRust will automatically retrieve temporary credentials when `repo3-s3-key-type=auto`, which means that keys do not need to be explicitly set in `/etc/pgbackrust/pgbackrust.conf`.

This sample Amazon S3 policy will restrict all reads and writes to the bucket and repository path.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::demo-bucket"
            ],
            "Condition": {
                "StringEquals": {
                    "s3:prefix": [
                        "",
                        "demo-repo"
                    ],
                    "s3:delimiter": [
                        "/"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::demo-bucket"
            ],
            "Condition": {
                "StringLike": {
                    "s3:prefix": [
                        "demo-repo/*"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:PutObjectTagging",
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::demo-bucket/demo-repo/*"
            ]
        }
    ]
}
```

Commands are run exactly as if the repository were stored on a local disk.

**`pg-primary`** — Create the stanza

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info stanza-create
```

File creation time in S3 is relatively slow so `backup`/`restore` performance is improved by enabling [file bundling](#file-bundling).

**`pg-primary`** — Backup the demo cluster

```
sudo -u postgres pgbackrust --stanza=demo --repo=3 --log-level-console=info backup
```

## SFTP Support

pgBackRust supports locating repositories on SFTP hosts. SFTP file transfer is relatively slow so commands benefit by increasing `process-max` to parallelize file transfer.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure SFTP

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
process-max=4
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-diff=2
repo1-retention-full=2
repo2-azure-account=pgbackrust
repo2-azure-container=demo-container
repo2-azure-key=YXpLZXk=
repo2-path=/demo-repo
repo2-retention-full=4
repo2-type=azure
repo3-path=/demo-repo
repo3-retention-full=4
repo3-s3-bucket=demo-bucket
repo3-s3-endpoint=s3.us-east-1.amazonaws.com
repo3-s3-key=accessKey1
repo3-s3-key-secret=verySecretKey1
repo3-s3-region=us-east-1
repo3-type=s3
repo4-bundle=y
repo4-path=/demo-repo
repo4-sftp-host=sftp-server
repo4-sftp-host-key-hash-type=sha1
repo4-sftp-host-user=pgbackrust
repo4-sftp-private-key-file=/var/lib/postgresql/.ssh/id_rsa_sftp
repo4-sftp-public-key-file=/var/lib/postgresql/.ssh/id_rsa_sftp.pub
repo4-type=sftp
start-fast=y

[global:archive-push]
compress-level=3
```

When utilizing SFTP, if libssh2 is compiled against OpenSSH then `repo4-sftp-public-key-file` is optional.

**`pg-primary`** — Generate SSH keypair for SFTP backup

```
sudo -u postgres mkdir -m 750 -p /var/lib/postgresql/.ssh
sudo -u postgres ssh-keygen -f /var/lib/postgresql/.ssh/id_rsa_sftp -t rsa -b 4096 -N "" -m PEM
```

**`sftp-server`** — Copy `pg-primary` SFTP backup public key to `sftp-server`

```
sudo -u pgbackrust mkdir -m 750 -p /home/pgbackrust/.ssh
sudo (sudo ssh root@pg-primary cat /var/lib/postgresql/.ssh/id_rsa_sftp.pub) | sudo -u pgbackrust tee \
    -a /home/pgbackrust/.ssh/authorized_keys
```

Commands are run exactly as if the repository were stored on a local disk.

**`pg-primary`** — Add sftp-server fingerprint to known_hosts file since `repo4-sftp-host-key-check-type` defaults to "strict"

```
sudo -u postgres ssh-keyscan -H sftp-server >> /var/lib/postgresql/.ssh/known_hosts 2>/dev/null
```

**`pg-primary`** — Create the stanza

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info stanza-create
```

**`pg-primary`** — Backup the demo cluster

```
sudo -u postgres pgbackrust --stanza=demo --repo=4 --log-level-console=info backup
```

## GCS-Compatible Object Store Support

pgBackRust supports locating repositories in GCS-compatible object stores. The bucket used to store the repository must be created in advance - pgBackRust will not do it automatically. The repository can be located in the bucket root (`/`) but it's usually best to place it in a subpath so object store logs or other data can also be stored in the bucket without conflicts.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure GCS

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
process-max=4
repo1-block=y
repo1-bundle=y
repo1-cipher-pass=zWaf6XtpjIVZC5444yXB+cgFDFl7MxGlgkZSaoPvTGirhPygu4jOKOXf9LO4vjfO
repo1-cipher-type=aes-256-cbc
repo1-path=/var/lib/pgbackrust
repo1-retention-diff=2
repo1-retention-full=2
repo2-azure-account=pgbackrust
repo2-azure-container=demo-container
repo2-azure-key=YXpLZXk=
repo2-path=/demo-repo
repo2-retention-full=4
repo2-type=azure
repo3-path=/demo-repo
repo3-retention-full=4
repo3-s3-bucket=demo-bucket
repo3-s3-endpoint=s3.us-east-1.amazonaws.com
repo3-s3-key=accessKey1
repo3-s3-key-secret=verySecretKey1
repo3-s3-region=us-east-1
repo3-type=s3
repo4-bundle=y
repo4-path=/demo-repo
repo4-sftp-host=sftp-server
repo4-sftp-host-key-hash-type=sha1
repo4-sftp-host-user=pgbackrust
repo4-sftp-private-key-file=/var/lib/postgresql/.ssh/id_rsa_sftp
repo4-sftp-public-key-file=/var/lib/postgresql/.ssh/id_rsa_sftp.pub
repo4-type=sftp
repo5-gcs-bucket=demo-bucket
repo5-gcs-key=/etc/pgbackrust/gcs-key.json
repo5-path=/demo-repo
repo5-type=gcs
start-fast=y

[global:archive-push]
compress-level=3
```

When running in GCE set `repo5-gcs-key-type=auto` to automatically authenticate using the instance service account.

Commands are run exactly as if the repository were stored on a local disk.

File creation time in GCS is relatively slow so `backup`/`restore` performance is improved by enabling [file bundling](#file-bundling).

## Target Time for Repository

The target time defines the time that commands use to read a repository on versioned storage. This allows the command to read the repository as it was at a point-in-time in order to recover data that has been deleted or corrupted by user accident or malware.

Versioned storage is supported by S3, GCS, and Azure but is generally not enabled by default. In addition to enabling versioning, it may be useful to enable object locking for S3 and soft delete for GCS or Azure.

When the `repo-target-time` option is specified then the `repo` option must also be provided. It is likely that not all repository types will support versioning and in general it makes sense to target a single repository for recovery.

Note that comparisons to the storage timestamp are <= the timestamp provided and milliseconds are truncated from the timestamp when provided.

To demonstrate this feature the `demo` stanza in the S3 repo is deleted.

**`pg-primary`** — Delete stanza in S3 repository

```
sudo pg_ctlcluster 17 demo stop
sudo -u postgres pgbackrust --stanza=demo stop
sudo -u postgres pgbackrust --stanza=demo --repo=3 stanza-delete
```

Once the stanza is deleted the `info` command will show the repository in an error state.

**`pg-primary`** — Error on info

```
sudo -u postgres pgbackrust --stanza=demo --repo=3 info
```

However, since the storage is versioned, it is possible to look at the repository at a time before the stanza was deleted. Finding the target time can be tricky depending on the situation, but in this case the time when the stanza was deleted can be determined by checking when `backup.info` was deleted.

**`s3-server`** — Use `mc` to list versions of `backup.info` in the bucket

```
sudo mc ls --versions s3/demo-bucket/demo-repo/backup/demo/backup.info
```

Now the `info` command can be run with a target time that will show the repository before it was deleted.

**`pg-primary`** — Info with target time

```
sudo -u postgres pgbackrust --stanza=demo --repo=3 --repo-target-time="<limit-time>" info
```

If the required backup is shown by the `info` command then it can be restored using the same target time.

**`pg-primary`** — Restore with target time

```
sudo -u postgres pgbackrust --stanza=demo --repo=3 --delta --repo-target-time="<limit-time>" \
    --log-level-console=info restore
sudo pg_ctlcluster 17 demo start
```

## Dedicated Repository Host

The configuration described in [Quickstart](#quick-start) is suitable for simple installations but for enterprise configurations it is more typical to have a dedicated `repository` host where the backups and WAL archive files are stored. This separates the backups and WAL archive from the database server so `database` host failures have less impact. It is still a good idea to employ traditional backup software to backup the `repository` host.

On PostgreSQL hosts, `pg1-path` is required to be the path of the local PostgreSQL cluster and no `pg1-host` should be configured. When configuring a repository host, the pgbackrust configuration file must have the `pg-host` option configured to connect to the primary and standby (if any) hosts. The repository host has the only pgbackrust configuration that should be aware of more than one PostgreSQL host. Order does not matter, e.g. pg1-path/pg1-host, pg2-path/pg2-host can be primary or standby.

### Installation

A new host named `repository` is created to store the cluster backups.

> **Note:** The pgBackRust version installed on the `repository` host must exactly match the version installed on the PostgreSQL host.

The `pgbackrust` user is created to own the pgBackRust repository. Any user can own the repository but it is best not to use `postgres` (if it exists) to avoid confusion.

**`repository`** — Create `pgbackrust` user

```
sudo adduser --disabled-password --gecos "" pgbackrust
```

Installing pgBackRust from a package is preferable to building from source. When installing from a package the rest of the instructions in this section are generally not required, but it is possible that a package will skip creating one of the directories or apply incorrect permissions. In that case it may be necessary to manually create directories or update permissions.

If packages are not provided for your distribution/version you can [build from source](#build) and then install manually as shown here.

**`repository`** — Install dependencies

```
sudo apt-get install postgresql-client libpq5 libssh2-1 zlib1g libbz2-1.0 liblz4-1 libzstd1 libssl3
```

**`repository`** — Copy pgBackRust binary from build host

```
sudo scp build:pgbackrust/target/release/pgbackrust /usr/bin
sudo chmod 755 /usr/bin/pgbackrust
```

pgBackRust requires log and configuration directories and a configuration file.

**`repository`** — Create pgBackRust configuration file and directories

```
sudo mkdir -p -m 770 /var/log/pgbackrust
sudo chown pgbackrust:pgbackrust /var/log/pgbackrust
sudo mkdir -p /etc/pgbackrust
sudo mkdir -p /etc/pgbackrust/conf.d
sudo touch /etc/pgbackrust/pgbackrust.conf
sudo chmod 640 /etc/pgbackrust/pgbackrust.conf
sudo chown pgbackrust:pgbackrust /etc/pgbackrust/pgbackrust.conf
```

**`repository`** — Create the pgBackRust repository

```
sudo mkdir -p /var/lib/pgbackrust
sudo chmod 750 /var/lib/pgbackrust
sudo chown pgbackrust:pgbackrust /var/lib/pgbackrust
```

### Setup Passwordless SSH

pgBackRust can use passwordless SSH to enable communication between the hosts.

**`repository`** — Create `repository` host key pair

```
sudo -u pgbackrust mkdir -m 750 /home/pgbackrust/.ssh
sudo -u pgbackrust ssh-keygen -f /home/pgbackrust/.ssh/id_rsa -t rsa -b 4096 -N ""
```

**`pg-primary`** — Create `pg-primary` host key pair

```
sudo -u postgres mkdir -m 750 -p /var/lib/postgresql/.ssh
sudo -u postgres ssh-keygen -f /var/lib/postgresql/.ssh/id_rsa -t rsa -b 4096 -N ""
```

Exchange keys between `repository` and `pg-primary`.

**`repository`** — Copy `pg-primary` public key to `repository`

```
sudo (echo -n 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding,' && echo -n \
    'command="/usr/bin/pgbackrust ${SSH_ORIGINAL_COMMAND#* }" ' && sudo ssh root@pg-primary cat \
    /var/lib/postgresql/.ssh/id_rsa.pub) | sudo -u pgbackrust tee -a \
    /home/pgbackrust/.ssh/authorized_keys
```

**`pg-primary`** — Copy `repository` public key to `pg-primary`

```
sudo (echo -n 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding,' && echo -n \
    'command="/usr/bin/pgbackrust ${SSH_ORIGINAL_COMMAND#* }" ' && sudo ssh root@repository cat \
    /home/pgbackrust/.ssh/id_rsa.pub) | sudo -u postgres tee -a \
    /var/lib/postgresql/.ssh/authorized_keys
```

Test that connections can be made from `repository` to `pg-primary` and vice versa.

**`repository`** — Test connection from `repository` to `pg-primary`

```
sudo -u pgbackrust ssh postgres@pg-primary
```

**`pg-primary`** — Test connection from `pg-primary` to `repository`

```
sudo -u postgres ssh pgbackrust@repository
```

> **Note:** ssh has been configured to only allow pgBackRust to be run via passwordless ssh. This enhances security in the event that one of the service accounts is hijacked.

### Configuration

The `repository` host must be configured with the `pg-primary` host/user and database path. The primary will be configured as `pg1` to allow a standby to be added later.

**`repository`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `pg1-host`/`pg1-host-user` and `pg1-path`

```ini
[demo]
pg1-host=pg-primary
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y
```

The database host must be configured with the repository host/user. The default for the `repo1-host-user` option is `pgbackrust`. If the `postgres` user does restores on the repository host it is best not to also allow the `postgres` user to perform backups. However, the `postgres` user can read the repository directly if it is in the same group as the `pgbackrust` user.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `repo1-host`/`repo1-host-user`

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-level-file=detail
log-timestamp=n
repo1-host=repository
```

PostgreSQL configuration may be found in the [Configure Archiving](#configure-archiving) section.

Commands are run the same as on a single host configuration except that some commands such as `backup` and `expire` are run from the `repository` host instead of the `database` host.

### Create and Check Stanza

Create the stanza in the new repository.

**`repository`** — Create the stanza

```
sudo -u pgbackrust pgbackrust --stanza=demo stanza-create
```

Check that the configuration is correct on both the `database` and `repository` hosts. More information about the `check` command can be found in [Check the Configuration](#check-the-configuration).

**`pg-primary`** — Check the configuration

```
sudo -u postgres pgbackrust --stanza=demo check
```

**`repository`** — Check the configuration

```
sudo -u pgbackrust pgbackrust --stanza=demo check
```

### Perform a Backup

To perform a backup of the PostgreSQL cluster run pgBackRust with the `backup` command on the `repository` host.

**`repository`** — Backup the demo cluster

```
sudo -u pgbackrust pgbackrust --stanza=demo backup
```

### Restore a Backup

To perform a restore of the PostgreSQL cluster run pgBackRust with the `restore` command on the `database` host.

**`pg-primary`** — Stop the demo cluster, restore, and restart PostgreSQL

```
sudo pg_ctlcluster 17 demo stop
sudo -u postgres pgbackrust --stanza=demo --delta restore
sudo pg_ctlcluster 17 demo start
```

## Parallel Backup / Restore

pgBackRust offers parallel processing to improve performance of compression and transfer. The number of processes to be used for this feature is set using the `--process-max` option.

It is usually best not to use more than 25% of available CPUs for the `backup` command. Backups don't have to run that fast as long as they are performed regularly and the backup process should not impact database performance, if at all possible.

The restore command can and should use all available CPUs because during a restore the PostgreSQL cluster is shut down and there is generally no other important work being done on the host. If the host contains multiple clusters then that should be considered when setting restore parallelism.

**`repository`** — Perform a backup with single process

```
sudo -u pgbackrust pgbackrust --stanza=demo --type=full backup
```

**`repository`:`/etc/pgbackrust/pgbackrust.conf`** — Configure pgBackRust to use multiple `backup` processes

```ini
[demo]
pg1-host=pg-primary
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
process-max=3
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y
```

**`repository`** — Perform a backup with multiple processes

```
sudo -u pgbackrust pgbackrust --stanza=demo --type=full backup
```

**`repository`** — Get backup info for the demo cluster

```
sudo -u pgbackrust pgbackrust info
```

The performance of the last backup should be improved by using multiple processes. For very small backups the difference may not be very apparent, but as the size of the database increases so will time savings.

## Starting and Stopping

If a standby is promoted for testing, or a test cluster is restored from a production backup, then it is a good idea to prevent those clusters from writing to pgBackRust repositories. This can be accomplished with the `stop` command.

The commands that write and are blocked by `stop` are: `archive-push`, `backup`, `expire`, `stanza-create`, and `stanza-upgrade`. Note that `stanza-delete` is an exception to this rule (see [Delete a Stanza](#delete-a-stanza) for more details).

**`pg-primary`** — Stop pgBackRust write commands

```
sudo -u postgres pgbackrust stop
```

New pgBackRust write commands will no longer run.

**`repository`** — Attempt a backup

```
sudo -u pgbackrust pgbackrust --stanza=demo backup
```

Specify the `--force` option to terminate any pgBackRust write commands that are currently running. This includes asynchronous archive-get (though it will run again if PostgreSQL requires it). If pgBackRust is already stopped then stopping again will generate a warning.

**`pg-primary`** — Stop the pgBackRust services again

```
sudo -u postgres pgbackrust stop
```

Start pgBackRust write commands again with the `start` command. Write commands that were in progress before the stop will not automatically start again, but they are now allowed to start.

**`pg-primary`** — Start pgBackRust write commands

```
sudo -u postgres pgbackrust start
```

It is also possible to stop pgBackRust for a single stanza.

**`pg-primary`** — Stop pgBackRust write commands for the `demo` stanza

```
sudo -u postgres pgbackrust --stanza=demo stop
```

New pgBackRust write commands for the specified stanza will no longer run.

**`repository`** — Attempt a backup

```
sudo -u pgbackrust pgbackrust --stanza=demo backup
```

The stanza must also be specified when starting pgBackRust write commands for a single stanza.

**`pg-primary`** — Start pgBackRust write commands for the `demo` stanza

```
sudo -u postgres pgbackrust --stanza=demo start
```

## Replication

Replication allows multiple copies of a PostgreSQL cluster (called standbys) to be created from a single primary. The standbys are useful for balancing reads and to provide redundancy in case the primary host fails.

### Installation

A new host named `pg-standby` is created to run the standby.

Installing pgBackRust from a package is preferable to building from source. When installing from a package the rest of the instructions in this section are generally not required, but it is possible that a package will skip creating one of the directories or apply incorrect permissions. In that case it may be necessary to manually create directories or update permissions.

If packages are not provided for your distribution/version you can [build from source](#build) and then install manually as shown here.

**`pg-standby`** — Install dependencies

```
sudo apt-get install postgresql-client libpq5 libssh2-1 zlib1g libbz2-1.0 liblz4-1 libzstd1 libssl3
```

**`pg-standby`** — Copy pgBackRust binary from build host

```
sudo scp build:pgbackrust/target/release/pgbackrust /usr/bin
sudo chmod 755 /usr/bin/pgbackrust
```

pgBackRust requires log and configuration directories and a configuration file.

**`pg-standby`** — Create pgBackRust configuration file and directories

```
sudo mkdir -p -m 770 /var/log/pgbackrust
sudo chown postgres:postgres /var/log/pgbackrust
sudo mkdir -p /etc/pgbackrust
sudo mkdir -p /etc/pgbackrust/conf.d
sudo touch /etc/pgbackrust/pgbackrust.conf
sudo chmod 640 /etc/pgbackrust/pgbackrust.conf
sudo chown postgres:postgres /etc/pgbackrust/pgbackrust.conf
```

### Setup Passwordless SSH

pgBackRust can use passwordless SSH to enable communication between the hosts.

**`pg-standby`** — Create `pg-standby` host key pair

```
sudo -u postgres mkdir -m 750 -p /var/lib/postgresql/.ssh
sudo -u postgres ssh-keygen -f /var/lib/postgresql/.ssh/id_rsa -t rsa -b 4096 -N ""
```

Exchange keys between `repository` and `pg-standby`.

**`repository`** — Copy `pg-standby` public key to `repository`

```
sudo (echo -n 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding,' && echo -n \
    'command="/usr/bin/pgbackrust ${SSH_ORIGINAL_COMMAND#* }" ' && sudo ssh root@pg-standby cat \
    /var/lib/postgresql/.ssh/id_rsa.pub) | sudo -u pgbackrust tee -a \
    /home/pgbackrust/.ssh/authorized_keys
```

**`pg-standby`** — Copy `repository` public key to `pg-standby`

```
sudo (echo -n 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding,' && echo -n \
    'command="/usr/bin/pgbackrust ${SSH_ORIGINAL_COMMAND#* }" ' && sudo ssh root@repository cat \
    /home/pgbackrust/.ssh/id_rsa.pub) | sudo -u postgres tee -a \
    /var/lib/postgresql/.ssh/authorized_keys
```

Test that connections can be made from `repository` to `pg-standby` and vice versa.

**`repository`** — Test connection from `repository` to `pg-standby`

```
sudo -u pgbackrust ssh postgres@pg-standby
```

**`pg-standby`** — Test connection from `pg-standby` to `repository`

```
sudo -u postgres ssh pgbackrust@repository
```

### Hot Standby

A hot standby performs replication using the WAL archive and allows read-only queries.

pgBackRust configuration is very similar to `pg-primary` except that the `standby` recovery type will be used to keep the cluster in recovery mode when the end of the WAL stream has been reached.

**`pg-standby`:`/etc/pgbackrust/pgbackrust.conf`** — Configure pgBackRust on the standby

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-level-file=detail
log-timestamp=n
repo1-host=repository
```

The demo cluster must be created (even though it will be overwritten on restore) in order to create the PostgreSQL configuration files.

**`pg-standby`** — Create demo cluster

```
sudo pg_createcluster 17 demo
```

Now the standby can be created with the `restore` command.

> **Important:** If the cluster is intended to be promoted without becoming the new primary (e.g. for reporting or testing), use `--archive-mode=off` or set `archive_mode=off` in `postgresql.conf` to disable archiving. If archiving is not disabled then the repository may be polluted with WAL that can make restores more difficult.

**`pg-standby`** — Restore the demo standby cluster

```
sudo -u postgres pgbackrust --stanza=demo --delta --type=standby restore
sudo -u postgres cat /var/lib/postgresql/17/demo/postgresql.auto.conf
```

The `hot_standby` setting must be enabled before starting PostgreSQL to allow read-only connections on `pg-standby`. Otherwise, connection attempts will be refused. The rest of the configuration is in case the standby is promoted to a primary.

**`pg-standby`:`/etc/postgresql/17/demo/postgresql.conf`** — Configure PostgreSQL

```ini
hot_standby = on
archive_command = 'pgbackrust --stanza=demo archive-push %p'
archive_mode = on
```

**`pg-standby`** — Start PostgreSQL

```
sudo pg_ctlcluster 17 demo start
```

The PostgreSQL log gives valuable information about the recovery. Note especially that the cluster has entered standby mode and is ready to accept read-only connections.

**`pg-standby`** — Examine the PostgreSQL log output for log messages indicating success

```
sudo -u postgres cat /var/log/postgresql/postgresql-17-demo.log
```

An easy way to test that replication is properly configured is to create a table on `pg-primary`.

**`pg-primary`** — Create a new table on the primary

```
sudo -u postgres psql -c " begin; create table replicated_table (message text); insert into replicated_table \
    values ('Important Data'); commit; select * from replicated_table";
```

And then query the same table on `pg-standby`.

**`pg-standby`** — Query new table on the standby

```
sudo -u postgres psql -c "select * from replicated_table;"
```

So, what went wrong? Since PostgreSQL is pulling WAL segments from the archive to perform replication, changes won't be seen on the standby until the WAL segment that contains those changes is pushed from `pg-primary`.

This can be done manually by calling `pg_switch_wal()` which pushes the current WAL segment to the archive (a new WAL segment is created to contain further changes).

**`pg-primary`** — Call `pg_switch_wal()`

```
sudo -u postgres psql -c "select *, current_timestamp from pg_switch_wal()";
```

Now after a short delay the table will appear on `pg-standby`.

**`pg-standby`** — Now the new table exists on the standby (may require a few retries)

```
sudo -u postgres psql -c " select *, current_timestamp from replicated_table"
```

Check the standby configuration for access to the repository.

**`pg-standby`** — Check the configuration

```
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info check
```

### Streaming Replication

Instead of relying solely on the WAL archive, streaming replication makes a direct connection to the primary and applies changes as soon as they are made on the primary. This results in much less lag between the primary and standby.

Streaming replication requires a user with the replication privilege.

**`pg-primary`** — Create replication user

```
sudo -u postgres psql -c " create user replicator password 'jw8s0F4' replication";
```

The `pg_hba.conf` file must be updated to allow the standby to connect as the replication user. Be sure to replace the IP address below with the actual IP address of your `pg-standby`. A reload will be required after modifying the `pg_hba.conf` file.

**`pg-primary`** — Create `pg_hba.conf` entry for replication user

```
sudo -u postgres sh -c 'echo "host replication replicator <pg-standby-ip>/32 md5" >> \
    /etc/postgresql/17/demo/pg_hba.conf'
sudo pg_ctlcluster 17 demo reload
```

The standby needs to know how to contact the primary so the `primary_conninfo` setting will be configured in pgBackRust.

**`pg-standby`:`/etc/pgbackrust/pgbackrust.conf`** — Set `primary_conninfo`

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo
recovery-option=primary_conninfo=host=<pg-primary-ip> port=5432 user=replicator

[global]
log-level-file=detail
log-timestamp=n
repo1-host=repository
```

It is possible to configure a password in the `primary_conninfo` setting but using a `.pgpass` file is more flexible and secure.

**`pg-standby`** — Configure the replication password in the `.pgpass` file.

```
sudo -u postgres sh -c 'echo "<pg-primary-ip>:*:replication:replicator:jw8s0F4" >> /var/lib/postgresql/.pgpass'
sudo -u postgres chmod 600 /var/lib/postgresql/.pgpass
```

Now the standby can be created with the `restore` command.

**`pg-standby`** — Stop PostgreSQL and restore the demo standby cluster

```
sudo pg_ctlcluster 17 demo stop
sudo -u postgres pgbackrust --stanza=demo --delta --type=standby restore
sudo -u postgres cat /var/lib/postgresql/17/demo/postgresql.auto.conf
```

> **Note:** The `primary_conninfo` setting has been written into the `postgresql.auto.conf` file because it was configured as a `recovery-option` in `pgbackrust.conf`. The `--type=preserve` option can be used with the `restore` to leave the existing `postgresql.auto.conf` file in place if that behavior is preferred.

**`pg-standby`** — Start PostgreSQL

```
sudo pg_ctlcluster 17 demo start
```

The PostgreSQL log will confirm that streaming replication has started.

**`pg-standby`** — Examine the PostgreSQL log output for log messages indicating success

```
sudo -u postgres cat /var/log/postgresql/postgresql-17-demo.log
```

Now when a table is created on `pg-primary` it will appear on `pg-standby` quickly and without the need to call `pg_switch_wal()`.

**`pg-primary`** — Create a new table on the primary

```
sudo -u postgres psql -c " begin; create table stream_table (message text); insert into stream_table values \
    ('Important Data'); commit; select *, current_timestamp from stream_table";
```

**`pg-standby`** — Query table on the standby

```
sudo -u postgres psql -c " select *, current_timestamp from stream_table"
```

## Multiple Stanzas

pgBackRust supports multiple stanzas. The most common usage is sharing a `repository` host among multiple stanzas.

### Installation

A new host named `pg-alt` is created to run the new primary.

Installing pgBackRust from a package is preferable to building from source. When installing from a package the rest of the instructions in this section are generally not required, but it is possible that a package will skip creating one of the directories or apply incorrect permissions. In that case it may be necessary to manually create directories or update permissions.

If packages are not provided for your distribution/version you can [build from source](#build) and then install manually as shown here.

**`pg-alt`** — Install dependencies

```
sudo apt-get install postgresql-client libpq5 libssh2-1 zlib1g libbz2-1.0 liblz4-1 libzstd1 libssl3
```

**`pg-alt`** — Copy pgBackRust binary from build host

```
sudo scp build:pgbackrust/target/release/pgbackrust /usr/bin
sudo chmod 755 /usr/bin/pgbackrust
```

pgBackRust requires log and configuration directories and a configuration file.

**`pg-alt`** — Create pgBackRust configuration file and directories

```
sudo mkdir -p -m 770 /var/log/pgbackrust
sudo chown postgres:postgres /var/log/pgbackrust
sudo mkdir -p /etc/pgbackrust
sudo mkdir -p /etc/pgbackrust/conf.d
sudo touch /etc/pgbackrust/pgbackrust.conf
sudo chmod 640 /etc/pgbackrust/pgbackrust.conf
sudo chown postgres:postgres /etc/pgbackrust/pgbackrust.conf
```

### Setup Passwordless SSH

pgBackRust can use passwordless SSH to enable communication between the hosts.

**`pg-alt`** — Create `pg-alt` host key pair

```
sudo -u postgres mkdir -m 750 -p /var/lib/postgresql/.ssh
sudo -u postgres ssh-keygen -f /var/lib/postgresql/.ssh/id_rsa -t rsa -b 4096 -N ""
```

Exchange keys between `repository` and `pg-alt`.

**`repository`** — Copy `pg-alt` public key to `repository`

```
sudo (echo -n 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding,' && echo -n \
    'command="/usr/bin/pgbackrust ${SSH_ORIGINAL_COMMAND#* }" ' && sudo ssh root@pg-alt cat \
    /var/lib/postgresql/.ssh/id_rsa.pub) | sudo -u pgbackrust tee -a \
    /home/pgbackrust/.ssh/authorized_keys
```

**`pg-alt`** — Copy `repository` public key to `pg-alt`

```
sudo (echo -n 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding,' && echo -n \
    'command="/usr/bin/pgbackrust ${SSH_ORIGINAL_COMMAND#* }" ' && sudo ssh root@repository cat \
    /home/pgbackrust/.ssh/id_rsa.pub) | sudo -u postgres tee -a \
    /var/lib/postgresql/.ssh/authorized_keys
```

Test that connections can be made from `repository` to `pg-alt` and vice versa.

**`repository`** — Test connection from `repository` to `pg-alt`

```
sudo -u pgbackrust ssh postgres@pg-alt
```

**`pg-alt`** — Test connection from `pg-alt` to `repository`

```
sudo -u postgres ssh pgbackrust@repository
```

### Configuration

pgBackRust configuration is nearly identical to `pg-primary` except that the `demo-alt` stanza will be used so backups and archive will be stored in a separate location.

**`pg-alt`:`/etc/pgbackrust/pgbackrust.conf`** — Configure pgBackRust on the new primary

```ini
[demo-alt]
pg1-path=/var/lib/postgresql/17/demo

[global]
log-level-file=detail
log-timestamp=n
repo1-host=repository
```

**`repository`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `pg1-host`/`pg1-host-user` and `pg1-path`

```ini
[demo]
pg1-host=pg-primary
pg1-path=/var/lib/postgresql/17/demo

[demo-alt]
pg1-host=pg-alt
pg1-path=/var/lib/postgresql/17/demo

[global]
log-timestamp=n
process-max=3
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y
```

### Setup Demo Cluster

**`pg-alt`** — Create the demo cluster

```
sudo -u postgres /usr/lib/postgresql/17/bin/initdb -D /var/lib/postgresql/17/demo -k -A peer
sudo pg_createcluster 17 demo
```

**`pg-alt`:`/etc/postgresql/17/demo/postgresql.conf`** — Configure PostgreSQL settings

```ini
archive_command = 'pgbackrust --stanza=demo-alt archive-push %p'
archive_mode = on
```

**`pg-alt`** — Start the demo cluster

```
sudo pg_ctlcluster 17 demo restart
```

### Create the Stanza and Check Configuration

The `stanza-create` command must be run to initialize the stanza. It is recommended that the `check` command be run after `stanza-create` to ensure archiving and backups are properly configured.

**`pg-alt`** — Create the stanza and check the configuration

```
sudo -u postgres pgbackrust --stanza=demo-alt --log-level-console=info stanza-create
sudo -u postgres pgbackrust --log-level-console=info check
```

If the `check` command is run from the `repository` host then all stanzas will be checked.

**`repository`** — Check the configuration for all stanzas

```
sudo -u pgbackrust pgbackrust --log-level-console=info check
```

## Asynchronous Archiving

Asynchronous archiving is enabled with the `archive-async` option. This option enables asynchronous operation for both the `archive-push` and `archive-get` commands.

A spool path is required. The commands will store transient data here but each command works quite a bit differently so spool path usage is described in detail in each section.

**`pg-primary`** — Create the spool directory

```
sudo mkdir -p -m 750 /var/spool/pgbackrust
sudo chown postgres:postgres /var/spool/pgbackrust
```

**`pg-standby`** — Create the spool directory

```
sudo mkdir -p -m 750 /var/spool/pgbackrust
sudo chown postgres:postgres /var/spool/pgbackrust
```

The spool path must be configured and asynchronous archiving enabled. Asynchronous archiving automatically confers some benefit by reducing the number of connections made to remote storage, but setting `process-max` can drastically improve performance by parallelizing operations. Be sure not to set `process-max` so high that it affects normal database operations.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Configure the spool path and asynchronous archiving

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo

[global]
archive-async=y
log-level-file=detail
log-timestamp=n
repo1-host=repository
spool-path=/var/spool/pgbackrust

[global:archive-get]
process-max=2

[global:archive-push]
process-max=2
```

**`pg-standby`:`/etc/pgbackrust/pgbackrust.conf`** — Configure the spool path and asynchronous archiving

```ini
[demo]
pg1-path=/var/lib/postgresql/17/demo
recovery-option=primary_conninfo=host=<pg-primary-ip> port=5432 user=replicator

[global]
archive-async=y
log-level-file=detail
log-timestamp=n
repo1-host=repository
spool-path=/var/spool/pgbackrust

[global:archive-get]
process-max=2

[global:archive-push]
process-max=2
```

> **Note:** `process-max` is configured using command sections so that the option is not used by backup and restore. This also allows different values for `archive-push` and `archive-get`.

For demonstration purposes streaming replication will be broken to force PostgreSQL to get WAL using the `restore_command`.

**`pg-primary`** — Break streaming replication by changing the replication password

```
sudo -u postgres psql -c "alter user replicator password 'bogus'"
```

**`pg-standby`** — Restart standby to break connection

```
sudo pg_ctlcluster 17 demo restart
```

### Archive Push

The asynchronous `archive-push` command offloads WAL archiving to a separate process (or processes) to improve throughput. It works by "looking ahead" to see which WAL segments are ready to be archived beyond the request that PostgreSQL is currently making via the `archive_command`. WAL segments are transferred to the archive directly from the `pg_xlog`/`pg_wal` directory and success is only returned by the `archive_command` when the WAL segment has been safely stored in the archive.

The spool path holds the current status of WAL archiving. Status files written into the spool directory are typically zero length and should consume a minimal amount of space (a few MB at most) and very little IO. All the information in this directory can be recreated so it is not necessary to preserve the spool directory if the cluster is moved to new hardware.

> **Important:** In the original implementation of asynchronous archiving, WAL segments were copied to the spool directory before compression and transfer. The new implementation copies WAL directly from the `pg_xlog` directory. If asynchronous archiving was utilized in v1.12 or prior, read the v1.13 release notes carefully before upgrading.

The `[stanza]-archive-push-async.log` file can be used to monitor the activity of the asynchronous process. A good way to test this is to quickly push a number of WAL segments.

**`pg-primary`** — Test parallel asynchronous archiving

```
sudo -u postgres psql -c " select pg_create_restore_point('test async push'); select pg_switch_wal(); select \
    pg_create_restore_point('test async push'); select pg_switch_wal(); select \
    pg_create_restore_point('test async push'); select pg_switch_wal(); select \
    pg_create_restore_point('test async push'); select pg_switch_wal(); select \
    pg_create_restore_point('test async push'); select pg_switch_wal();"
sudo -u postgres pgbackrust --stanza=demo --log-level-console=info check
```

Now the log file will contain parallel, asynchronous activity.

**`pg-primary`** — Check results in the log

```
sudo -u postgres cat /var/log/pgbackrust/demo-archive-push-async.log
```

### Archive Get

The asynchronous `archive-get` command maintains a local queue of WAL to improve throughput. If a WAL segment is not found in the queue it is fetched from the repository along with enough consecutive WAL to fill the queue. The maximum size of the queue is defined by `archive-get-queue-max`. Whenever the queue is less than half full more WAL will be fetched to fill it.

Asynchronous operation is most useful in environments that generate a lot of WAL or have a high latency connection to the repository storage (i.e., S3 or other object stores). In the case of a high latency connection it may be a good idea to increase `process-max`.

The `[stanza]-archive-get-async.log` file can be used to monitor the activity of the asynchronous process.

**`pg-standby`** — Check results in the log

```
sudo -u postgres cat /var/log/pgbackrust/demo-archive-get-async.log
```

**`pg-primary`** — Fix streaming replication by changing the replication password

```
sudo -u postgres psql -c "alter user replicator password 'jw8s0F4'"
```

## Backup from a Standby

pgBackRust can perform backups on a standby instead of the primary. Standby backups require the `pg-standby` host to be configured and the `backup-standby` option enabled. If more than one standby is configured then the first running standby found will be used for the backup.

**`repository`:`/etc/pgbackrust/pgbackrust.conf`** — Configure `pg2-host`/`pg2-host-user` and `pg2-path`

```ini
[demo]
pg1-host=pg-primary
pg1-path=/var/lib/postgresql/17/demo
pg2-host=pg-standby
pg2-path=/var/lib/postgresql/17/demo

[demo-alt]
pg1-host=pg-alt
pg1-path=/var/lib/postgresql/17/demo

[global]
backup-standby=y
log-timestamp=n
process-max=3
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y
```

Both the primary and standby databases are required to perform the backup, though the vast majority of the files will be copied from the standby to reduce load on the primary. The database hosts can be configured in any order. pgBackRust will automatically determine which is the primary and which is the standby.

**`repository`** — Backup the demo cluster from `pg2`

```
sudo -u pgbackrust pgbackrust --stanza=demo --log-level-console=detail backup
```

This incremental backup shows that most of the files are copied from the `pg-standby` host and only a few are copied from the `pg-primary` host.

pgBackRust creates a standby backup that is identical to a backup performed on the primary. It does this by starting/stopping the backup on the `pg-primary` host, copying only files that are replicated from the `pg-standby` host, then copying the remaining few files from the `pg-primary` host. This means that logs and statistics from the primary database will be included in the backup.

## Upgrading PostgreSQL

Immediately after upgrading PostgreSQL to a newer major version, the `pg-path` for all pgBackRust configurations must be set to the new database location and the `stanza-upgrade` command run. If there is more than one repository configured on the host, the stanza will be upgraded on each. If the database is offline use the `--no-online` option.

The following instructions are not meant to be a comprehensive guide for upgrading PostgreSQL, rather they outline the general process for upgrading a primary and standby with the intent of demonstrating the steps required to reconfigure pgBackRust. It is recommended that a backup be taken prior to upgrading.

**`pg-primary`** — Stop old cluster

```
sudo pg_ctlcluster 17 demo stop
```

Stop the old cluster on the standby since it will be restored from the newly upgraded cluster.

**`pg-standby`** — Stop old cluster

```
sudo pg_ctlcluster 17 demo stop
```

Create the new cluster and perform upgrade.

**`pg-primary`** — Create new cluster and perform the upgrade

```
sudo -u postgres /usr/lib/postgresql/18/bin/initdb -D /var/lib/postgresql/18/demo -k -A peer
sudo pg_createcluster 18 demo
sudo -u postgres sh -c 'cd /var/lib/postgresql && /usr/lib/postgresql/18/bin/pg_upgrade \
    --old-bindir=/usr/lib/postgresql/17/bin --new-bindir=/usr/lib/postgresql/18/bin \
    --old-datadir=/var/lib/postgresql/17/demo --new-datadir=/var/lib/postgresql/18/demo \
    --old-options=" -c config_file=/etc/postgresql/17/demo/postgresql.conf" --new-options=" -c \
    config_file=/etc/postgresql/18/demo/postgresql.conf"'
```

Configure the new cluster settings and port.

**`pg-primary`:`/etc/postgresql/18/demo/postgresql.conf`** — Configure PostgreSQL

```ini
archive_command = 'pgbackrust --stanza=demo archive-push %p'
archive_mode = on
```

Update the pgBackRust configuration on all systems to point to the new cluster.

**`pg-primary`:`/etc/pgbackrust/pgbackrust.conf`** — Upgrade the `pg1-path`

```ini
[demo]
pg1-path=/var/lib/postgresql/18/demo

[global]
archive-async=y
log-level-file=detail
log-timestamp=n
repo1-host=repository
spool-path=/var/spool/pgbackrust

[global:archive-get]
process-max=2

[global:archive-push]
process-max=2
```

**`pg-standby`:`/etc/pgbackrust/pgbackrust.conf`** — Upgrade the `pg-path`

```ini
[demo]
pg1-path=/var/lib/postgresql/18/demo
recovery-option=primary_conninfo=host=<pg-primary-ip> port=5432 user=replicator

[global]
archive-async=y
log-level-file=detail
log-timestamp=n
repo1-host=repository
spool-path=/var/spool/pgbackrust

[global:archive-get]
process-max=2

[global:archive-push]
process-max=2
```

**`repository`:`/etc/pgbackrust/pgbackrust.conf`** — Upgrade `pg1-path` and `pg2-path`, disable backup from standby

```ini
[demo]
pg1-host=pg-primary
pg1-path=/var/lib/postgresql/18/demo
pg2-host=pg-standby
pg2-path=/var/lib/postgresql/18/demo

[demo-alt]
pg1-host=pg-alt
pg1-path=/var/lib/postgresql/17/demo

[global]
backup-standby=n
log-timestamp=n
process-max=3
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y
```

**`pg-primary`** — Copy hba configuration

```
sudo cp /etc/postgresql/17/demo/pg_hba.conf /etc/postgresql/18/demo/pg_hba.conf
```

Before starting the new cluster, the `stanza-upgrade` command must be run.

**`pg-primary`** — Upgrade the stanza

```
sudo -u postgres pgbackrust --stanza=demo --no-online --log-level-console=info stanza-upgrade
```

Start the new cluster and confirm it is successfully installed.

**`pg-primary`** — Start new cluster

```
sudo pg_ctlcluster 18 demo start
```

Test configuration using the `check` command.

**`pg-primary`** — Check configuration

```
sudo pg_lsclusters
sudo -u postgres pgbackrust --stanza=demo check
```

Remove the old cluster.

**`pg-primary`** — Remove old cluster

```
sudo pg_dropcluster 17 demo
```

Install the new PostgreSQL binaries on the standby and create the cluster.

**`pg-standby`** — Remove old cluster and create the new cluster

```
sudo pg_dropcluster 17 demo
sudo pg_createcluster 18 demo
```

Run the `check` on the repository host. The warning regarding the standby being down is expected since the standby cluster is down. Running this command demonstrates that the repository server is aware of the standby and is configured properly for the primary server.

**`repository`** — Check configuration

```
sudo -u pgbackrust pgbackrust --stanza=demo check
```

Run a full backup on the new cluster and then restore the standby from the backup. The backup type will automatically be changed to `full` if `incr` or `diff` is requested.

**`repository`** — Run a full backup

```
sudo -u pgbackrust pgbackrust --stanza=demo --type=full backup
```

**`pg-standby`** — Restore the demo standby cluster

```
sudo -u postgres pgbackrust --stanza=demo --delta --type=standby restore
```

**`pg-standby`:`/etc/postgresql/18/demo/postgresql.conf`** — Configure PostgreSQL

```ini
hot_standby = on
```

**`pg-standby`** — Start PostgreSQL and check the pgBackRust configuration

```
sudo pg_ctlcluster 18 demo start
sudo -u postgres pgbackrust --stanza=demo check
```

Backup from standby can be enabled now that the standby is restored.

**`repository`:`/etc/pgbackrust/pgbackrust.conf`** — Reenable backup from standby

```ini
[demo]
pg1-host=pg-primary
pg1-path=/var/lib/postgresql/18/demo
pg2-host=pg-standby
pg2-path=/var/lib/postgresql/18/demo

[demo-alt]
pg1-host=pg-alt
pg1-path=/var/lib/postgresql/17/demo

[global]
backup-standby=y
log-timestamp=n
process-max=3
repo1-path=/var/lib/pgbackrust
repo1-retention-full=2
start-fast=y
```
