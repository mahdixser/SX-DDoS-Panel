mod ui;
mod attack;
mod protocols;
mod proxy;
mod logger;
mod config;
mod tor;
mod bypass;

use ui::Panel;

#[tokio::main]
async fn main() {
    let mut panel = Panel::new();
    panel.run().await;
}
