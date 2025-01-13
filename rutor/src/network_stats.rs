use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct NetworkStats {
    pub download: u64,
    pub upload: u64,
    pub download_rate: u32,
    pub upload_rate: u32,
}

#[derive(Debug, Clone)]
pub struct NetworkStatsAccum {
    total_download: u64,
    total_upload: u64,
    download_rate: u32,
    upload_rate: u32,
    download_acum: u32,
    upload_acum: u32,
    last_download: Instant,
    last_upload: Instant,
    period: Duration,
}

impl NetworkStatsAccum {
    pub fn new(period: Duration) -> Self {
        Self {
            total_download: 0,
            total_upload: 0,
            download_rate: 0,
            upload_rate: 0,
            download_acum: 0,
            upload_acum: 0,
            last_download: Instant::now(),
            last_upload: Instant::now(),
            period,
        }
    }

    pub fn add_download(&mut self, num_bytes: u32) {
        self.total_download += num_bytes as u64;
        if self.last_download.elapsed() > self.period {
            self.last_download = Instant::now();
            self.download_rate = self.download_acum / self.period.as_secs() as u32;
            self.download_acum = num_bytes;
        } else {
            self.download_acum += num_bytes;
        }
    }

    pub fn add_upload(&mut self, num_bytes: u32) {
        self.total_upload += num_bytes as u64;
        if self.last_upload.elapsed() > self.period {
            self.last_upload = Instant::now();
            self.upload_rate = self.upload_acum / self.period.as_secs() as u32;
            self.upload_acum = num_bytes;
        } else {
            self.upload_acum += num_bytes;
        }
    }

    /// download rate in bytes/sec
    pub fn download_rate(&self) -> u32 {
        if self.last_download.elapsed() > self.period {
            0
        } else {
            self.download_rate
        }
    }

    /// upload rate in bytes/sec
    pub fn upload_rate(&self) -> u32 {
        if self.last_upload.elapsed() > self.period {
            0
        } else {
            self.upload_rate
        }
    }

    pub fn total_download(&self) -> u64 {
        self.total_download
    }

    pub fn total_upload(&self) -> u64 {
        self.total_upload
    }

    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            download: self.total_download(),
            upload: self.total_upload(),
            download_rate: self.download_rate(),
            upload_rate: self.upload_rate(),
        }
    }
}

impl Default for NetworkStatsAccum {
    fn default() -> Self {
        Self::new(Duration::from_secs_f64(1.5))
    }
}
