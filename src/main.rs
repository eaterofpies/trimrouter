#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    trimrouter::modes::run(args).await;
}
