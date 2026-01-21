use super::super::request::PanicReportRequest;
use crate::panic::BugReportHandler;
use crate::panic::PanicInfo;
use reqwest::StatusCode;
use reqwest::Url;
use std::str::FromStr;

// Default notify addr
// const NOTIFY_ADDR: &str = "http://127.0.0.1:40001/bugs/";

#[derive(Clone)]
pub struct HttpBugReporter {
    notify_addr: Url,
    client: reqwest::Client,
}

impl HttpBugReporter {
    pub fn new(addr: &str) -> Self {
        info!("new http bug reporter: {}", addr);

        let url = Url::from_str(addr).unwrap();
        Self {
            notify_addr: url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn notify(&self, req: PanicReportRequest) -> Result<(), Box<dyn std::error::Error>> {
        self.post(req).await
    }

    async fn post(&self, req: PanicReportRequest) -> Result<(), Box<dyn std::error::Error>> {
        let report_url = self.notify_addr.join(&req.info.hash).unwrap();

        let resp = self
            .client
            .post(report_url)
            .json(&req)
            .send()
            .await?;
        match resp.status() {
            StatusCode::OK => {
                info!("post to http notify addr success");

                Ok(())
            }
            code @ _ => {
                let body = resp.text().await;
                let msg = format!(
                    "post to http notify addr failed! addr={}, status={}, msg={:?}",
                    self.notify_addr, code, body
                );
                error!("{}", msg);
                Err(msg.into())
            }
        }
    }
}

impl BugReportHandler for HttpBugReporter {
    fn notify(
        &self,
        product_name: &str,
        service_name: &str,
        panic_info: &PanicInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = PanicReportRequest::new(product_name, service_name, panic_info.to_owned());
        let this = self.clone();

        tokio::runtime::Handle::current().block_on(async move {
            let _ = this.notify(req).await;
        });

        Ok(())
    }
}
