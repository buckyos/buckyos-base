//! A device's storage capacity from its mounted file systems.
//!
//! The mount table lists the same storage many times: container layers (each overlay mount
//! reports the size of the disk under it), bind mounts and btrfs subvolumes of one device,
//! APFS volumes sharing a container, ZFS datasets sharing a pool. Summing every entry
//! multiplies the capacity, so each piece of storage is counted once here.

use std::collections::HashMap;

/// One mounted file system as sysinfo (or `statvfs`) reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskSpaceSample {
    /// Source of the mount: `/dev/sda1`, `overlay`, `rpool/ROOT/ubuntu`, `C:\`, …
    pub device: String,
    pub file_system: String,
    pub mount_point: String,
    pub total: u64,
    pub available: u64,
}

impl DiskSpaceSample {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
}

/// Mounts that hold no storage of their own: memory-backed, container layers re-exposing the
/// disk below, read-only images, and remote shares that are not this device's disks.
fn holds_own_storage(file_system: &str) -> bool {
    let fs = file_system.trim().to_ascii_lowercase();
    if fs.starts_with("fuse.") {
        // `fuseblk` (ntfs-3g, exfat) is a local disk; `fuse.*` are virtual or remote.
        return false;
    }
    !matches!(
        fs.as_str(),
        "" | "overlay"
            | "overlayfs"
            | "aufs"
            | "tmpfs"
            | "devtmpfs"
            | "ramfs"
            | "squashfs"
            | "nsfs"
            | "autofs"
            | "iso9660"
            | "udf"
            | "nfs"
            | "nfs4"
            | "cifs"
            | "smb3"
            | "smbfs"
            | "9p"
            | "virtiofs"
    )
}

/// The storage a mount draws from: an APFS container (`/dev/disk3s5` → `/dev/disk3`), a ZFS
/// pool (`rpool/ROOT/ubuntu` → `rpool`), otherwise the device itself.
fn storage_root(device: &str, file_system: &str) -> String {
    if file_system.eq_ignore_ascii_case("apfs") {
        if let Some(rest) = device.strip_prefix("/dev/disk") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() && rest[digits.len()..].starts_with('s') {
                return format!("/dev/disk{digits}");
            }
        }
    }
    if file_system.eq_ignore_ascii_case("zfs") && !device.starts_with('/') {
        if let Some((pool, _)) = device.split_once('/') {
            return pool.to_string();
        }
    }
    device.to_string()
}

/// One sample per piece of storage, in first-seen order. Mounts of one storage share its free
/// space: when they also report the same size (bind mounts, APFS volumes) one of them stands
/// for all; when sizes differ (ZFS datasets: dataset usage + pool free) the usages add up and
/// the free space counts once.
pub fn distinct_disk_samples(
    samples: impl IntoIterator<Item = DiskSpaceSample>,
) -> Vec<DiskSpaceSample> {
    let mut groups: Vec<Vec<DiskSpaceSample>> = Vec::new();
    let mut index: HashMap<(String, String, u64), usize> = HashMap::new();
    for sample in samples {
        if sample.total == 0 || !holds_own_storage(&sample.file_system) {
            continue;
        }
        let file_system = sample.file_system.to_ascii_lowercase();
        let space_key = if file_system == "zfs" {
            sample.available
        } else {
            sample.total
        };
        let key = (
            storage_root(&sample.device, &file_system),
            file_system,
            space_key,
        );
        match index.get(&key) {
            Some(&slot) => groups[slot].push(sample),
            None => {
                index.insert(key, groups.len());
                groups.push(vec![sample]);
            }
        }
    }

    groups
        .into_iter()
        .map(|mut group| {
            let first = group.remove(0);
            let available = group.iter().fold(first.available, |available, other| {
                available.min(other.available)
            });
            if group.iter().all(|other| other.total == first.total) {
                return DiskSpaceSample { available, ..first };
            }
            let used = group
                .iter()
                .fold(first.used(), |sum, other| sum.saturating_add(other.used()));
            DiskSpaceSample {
                device: storage_root(&first.device, &first.file_system),
                total: used.saturating_add(available),
                available,
                ..first
            }
        })
        .collect()
}

/// `(total, used)` bytes over the distinct storage of `samples`.
pub fn distinct_disk_space(samples: impl IntoIterator<Item = DiskSpaceSample>) -> (u64, u64) {
    distinct_disk_samples(samples)
        .iter()
        .fold((0, 0), |(total, used), sample| {
            (
                total.saturating_add(sample.total),
                used.saturating_add(sample.used()),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn sample(device: &str, fs: &str, mount: &str, total: u64, available: u64) -> DiskSpaceSample {
        DiskSpaceSample {
            device: device.into(),
            file_system: fs.into(),
            mount_point: mount.into(),
            total,
            available,
        }
    }

    #[test]
    fn docker_overlays_do_not_multiply_the_root_disk() {
        // demo.buckyos.io: one 78 GiB disk and five container layers on it.
        let mut samples = vec![sample("/dev/sda", "ext4", "/", 78 * GIB, 37 * GIB)];
        for i in 0..5 {
            samples.push(sample(
                "overlay",
                "overlay",
                &format!("/var/lib/docker/rootfs/overlayfs/{i}"),
                78 * GIB,
                37 * GIB,
            ));
        }
        samples.push(sample("tmpfs", "tmpfs", "/dev/shm", 2 * GIB, 2 * GIB));
        assert_eq!(distinct_disk_space(samples), (78 * GIB, 41 * GIB));
    }

    #[test]
    fn bind_mounts_and_subvolumes_count_once_but_separate_disks_add_up() {
        let samples = vec![
            sample("/dev/nvme0n1p2", "btrfs", "/", 500 * GIB, 300 * GIB),
            sample("/dev/nvme0n1p2", "btrfs", "/home", 500 * GIB, 300 * GIB),
            sample(
                "/dev/nvme0n1p2",
                "btrfs",
                "/etc/hosts",
                500 * GIB,
                300 * GIB,
            ),
            // Two identical, still empty disks are still two disks.
            sample("/dev/sdb1", "ext4", "/mnt/a", 4000 * GIB, 4000 * GIB),
            sample("/dev/sdc1", "ext4", "/mnt/b", 4000 * GIB, 4000 * GIB),
            sample("nas:/share", "nfs4", "/mnt/nas", 9000 * GIB, 1000 * GIB),
        ];
        let distinct = distinct_disk_samples(samples);
        assert_eq!(distinct.len(), 3);
        assert_eq!(distinct_disk_space(distinct), (8500 * GIB, 200 * GIB));
    }

    #[test]
    fn apfs_volumes_of_one_container_count_once() {
        let samples = vec![
            sample("/dev/disk3s1s1", "apfs", "/", 994 * GIB, 600 * GIB),
            sample(
                "/dev/disk3s5",
                "apfs",
                "/System/Volumes/Data",
                994 * GIB,
                600 * GIB,
            ),
            sample(
                "/dev/disk3s6",
                "apfs",
                "/System/Volumes/VM",
                994 * GIB,
                600 * GIB,
            ),
            sample(
                "/dev/disk5s1",
                "apfs",
                "/Volumes/Backup",
                2000 * GIB,
                1500 * GIB,
            ),
        ];
        assert_eq!(distinct_disk_space(samples), (2994 * GIB, 894 * GIB));
    }

    #[test]
    fn macos_volume_names_count_once_when_free_space_changes_between_mounts() {
        let total = 994_662_584_320;
        let available = 393_558_260_265;
        let mut samples = vec![
            sample("Macintosh HD", "apfs", "/", total, available),
            sample(
                "Macintosh HD",
                "apfs",
                "/System/Volumes/Data",
                total,
                available - 4096,
            ),
        ];
        for _ in 0..2 {
            let distinct = distinct_disk_samples(samples.clone());
            assert_eq!(distinct.len(), 1);
            assert_eq!(distinct[0].available, available - 4096);
            assert_eq!(
                distinct_disk_space(distinct),
                (total, total - available + 4096)
            );
            samples.reverse();
        }
    }

    #[test]
    fn bind_mounts_count_once_when_free_space_changes_between_mounts() {
        let samples = vec![
            sample("/dev/nvme0n1p2", "btrfs", "/", 500 * GIB, 300 * GIB),
            sample(
                "/dev/nvme0n1p2",
                "btrfs",
                "/home",
                500 * GIB,
                300 * GIB - 4096,
            ),
            sample(
                "/dev/nvme0n1p2",
                "btrfs",
                "/etc/hosts",
                500 * GIB,
                300 * GIB + 4096,
            ),
        ];
        assert_eq!(distinct_disk_space(samples), (500 * GIB, 200 * GIB + 4096));
    }

    #[test]
    fn separate_disks_with_identical_capacity_and_free_space_still_add_up() {
        let samples = vec![
            sample("/dev/sdb1", "ext4", "/mnt/a", 4000 * GIB, 3000 * GIB),
            sample("/dev/sdc1", "ext4", "/mnt/b", 4000 * GIB, 3000 * GIB),
        ];
        let distinct = distinct_disk_samples(samples);
        assert_eq!(distinct.len(), 2);
        assert_eq!(distinct_disk_space(distinct), (8000 * GIB, 2000 * GIB));
    }

    #[test]
    fn non_apfs_partitions_of_one_macos_disk_remain_separate() {
        for file_system in ["hfs", "exfat"] {
            for available in [200 * GIB, 300 * GIB] {
                let samples = vec![
                    sample(
                        "/dev/disk4s1",
                        file_system,
                        "/Volumes/A",
                        500 * GIB,
                        300 * GIB,
                    ),
                    sample(
                        "/dev/disk4s2",
                        file_system,
                        "/Volumes/B",
                        500 * GIB,
                        available,
                    ),
                ];
                let distinct = distinct_disk_samples(samples);
                assert_eq!(distinct.len(), 2);
                assert_eq!(distinct[0].device, "/dev/disk4s1");
                assert_eq!(distinct[1].device, "/dev/disk4s2");
                assert_eq!(
                    distinct_disk_space(distinct),
                    (1000 * GIB, 700 * GIB - available)
                );
            }
        }
    }

    #[test]
    fn zfs_datasets_add_their_usage_and_share_the_pool_free_space() {
        let samples = vec![
            sample("rpool/ROOT/ubuntu", "zfs", "/", 110 * GIB, 100 * GIB),
            sample(
                "rpool/USERDATA/alice",
                "zfs",
                "/home/alice",
                140 * GIB,
                100 * GIB,
            ),
            sample("rpool/var", "zfs", "/var", 105 * GIB, 100 * GIB),
        ];
        let distinct = distinct_disk_samples(samples);
        assert_eq!(distinct.len(), 1);
        assert_eq!(distinct[0].device, "rpool");
        assert_eq!(distinct_disk_space(distinct), (155 * GIB, 55 * GIB));
    }

    #[test]
    fn zfs_datasets_with_different_free_space_remain_separate() {
        let samples = vec![
            sample("rpool/ROOT/ubuntu", "zfs", "/", 110 * GIB, 100 * GIB),
            sample(
                "rpool/USERDATA/alice",
                "zfs",
                "/home/alice",
                110 * GIB,
                90 * GIB,
            ),
        ];
        let distinct = distinct_disk_samples(samples);
        assert_eq!(distinct.len(), 2);
        assert_eq!(distinct_disk_space(distinct), (220 * GIB, 30 * GIB));
    }

    #[test]
    fn windows_drives_and_fuseblk_are_real_disks() {
        let samples = vec![
            sample("C:\\", "NTFS", "C:\\", 476 * GIB, 120 * GIB),
            sample("D:\\", "NTFS", "D:\\", 931 * GIB, 400 * GIB),
            sample("/dev/sdd1", "fuseblk", "/media/usb", 64 * GIB, 60 * GIB),
            sample("lxcfs", "fuse.lxcfs", "/var/lib/lxcfs", 0, 0),
        ];
        assert_eq!(distinct_disk_space(samples), (1471 * GIB, 891 * GIB));
    }
}
