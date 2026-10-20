use bytes::Bytes;
use h2::server::{self, SendResponse};
use h2::RecvStream;
use http::Request;

use std::future::Future;
use std::{
    error::Error,
    time::{Duration, Instant},
};

use tokio::net::{TcpListener, TcpStream};

const NUM_REQUESTS_TO_SEND: usize = 100_000;

// The actual server.
async fn server(addr: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        if let Ok((socket, _peer_addr)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = serve(socket).await {
                    println!("  -> err={:?}", e);
                }
            });
        }
    }
}

async fn serve(socket: TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut connection = server::handshake(socket).await?;
    while let Some(result) = connection.accept().await {
        let (request, respond) = result?;
        tokio::spawn(async move {
            if let Err(e) = handle_request(request, respond).await {
                println!("error while handling request: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_request(
    mut request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let body = request.body_mut();
    while let Some(data) = body.data().await {
        let data = data?;
        let _ = body.flow_control().release_capacity(data.len());
    }
    let response = http::Response::new(());
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"pong"), true)?;

    Ok(())
}

// The benchmark
async fn h2_send_requests(addr: &str) -> Result<(), Box<dyn Error>> {
    let tcp = loop {
        let Ok(tcp) = TcpStream::connect(addr).await else {
            continue;
        };
        break tcp;
    };
    let (client, h2) = h2::client::handshake(tcp).await?;
    // Spawn a task to run the conn...
    tokio::spawn(async move {
        if let Err(e) = h2.await {
            println!("GOT ERR={:?}", e);
        }
    });

    let mut handles = Vec::with_capacity(NUM_REQUESTS_TO_SEND);
    for _i in 0..NUM_REQUESTS_TO_SEND {
        let mut client = client.clone();
        let task = tokio::spawn(async move {
            let request = Request::builder().body(()).unwrap();

            let instant = Instant::now();
            let (response, _) = client.send_request(request, true).unwrap();
            let response = response.await.unwrap();
            let mut body = response.into_body();
            while let Some(_chunk) = body.data().await {}
            instant.elapsed()
        });
        handles.push(task);
    }

    let instant = Instant::now();
    let mut result = Vec::with_capacity(NUM_REQUESTS_TO_SEND);
    for handle in handles {
        result.push(handle.await.unwrap());
    }
    let mut sum = Duration::new(0, 0);
    for r in result.iter() {
        sum = sum.checked_add(*r).unwrap();
    }

    println!("Overall: {}ms.", instant.elapsed().as_millis());
    println!("Fastest: {}ms", result.iter().min().unwrap().as_millis());
    println!("Slowest: {}ms", result.iter().max().unwrap().as_millis());
    println!(
        "Avg    : {}ms",
        sum.div_f64(NUM_REQUESTS_TO_SEND as f64).as_millis()
    );
    Ok(())
}

async fn parking_lot_h2_send_requests(addr: &str) -> Result<(), Box<dyn Error>> {
    let tcp = loop {
        let Ok(tcp) = TcpStream::connect(addr).await else {
            continue;
        };
        break tcp;
    };
    let (client, h2) = http2::client::handshake(tcp).await?;
    // Spawn a task to run the conn...
    tokio::spawn(async move {
        if let Err(e) = h2.await {
            println!("GOT ERR={:?}", e);
        }
    });

    let mut handles = Vec::with_capacity(NUM_REQUESTS_TO_SEND);
    for _i in 0..NUM_REQUESTS_TO_SEND {
        let mut client = client.clone();
        let task = tokio::spawn(async move {
            let request = Request::builder().body(()).unwrap();

            let instant = Instant::now();
            let (response, _) = client.send_request(request, true).unwrap();
            let response = response.await.unwrap();
            let mut body = response.into_body();
            while let Some(_chunk) = body.data().await {}
            instant.elapsed()
        });
        handles.push(task);
    }

    let instant = Instant::now();
    let mut result = Vec::with_capacity(NUM_REQUESTS_TO_SEND);
    for handle in handles {
        result.push(handle.await.unwrap());
    }
    let mut sum = Duration::new(0, 0);
    for r in result.iter() {
        sum = sum.checked_add(*r).unwrap();
    }

    println!("Overall: {}ms.", instant.elapsed().as_millis());
    println!("Fastest: {}ms", result.iter().min().unwrap().as_millis());
    println!("Slowest: {}ms", result.iter().max().unwrap().as_millis());
    println!(
        "Avg    : {}ms",
        sum.div_f64(NUM_REQUESTS_TO_SEND as f64).as_millis()
    );
    Ok(())
}

fn spawn_single_thread_server(addr: &'static str) {
    println!("\n\n===============================");
    println!("Starting single-threaded server at {addr}");
    println!("===============================");
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(server(addr)).unwrap();
    });
    std::thread::sleep(Duration::from_millis(500));
}

fn spawn_multi_thread_server(addr: &'static str) {
    println!("\n\n===============================");
    println!("Starting multi-threaded server at {addr}");
    println!("===============================");
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(server(addr)).unwrap();
    });
    std::thread::sleep(Duration::from_millis(500));
}

fn run_single_thread_client<F: Future>(desc: &str, addr: &str, future: F) {
    println!("-------------------------------");
    println!("Single-threaded client: {desc} at {addr}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(future);
}

fn run_multi_thread_client<F: Future>(desc: &str, addr: &str, future: F) {
    println!("-------------------------------");
    println!("Multi-threaded client: {desc} at {addr}");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(future);
}

fn main() {
    let _ = env_logger::try_init();

    println!("===============================");
    println!("Benchmarking with concurrency = {}", NUM_REQUESTS_TO_SEND);
    println!("===============================");

    let addr = "127.0.0.1:5928";
    spawn_single_thread_server(addr);
    run_single_thread_client("h2_send_requests", addr, h2_send_requests(addr));
    run_single_thread_client(
        "parking_lot_h2_send_requests",
        addr,
        parking_lot_h2_send_requests(addr),
    );

    // Single-threaded server, multi-threaded client
    run_multi_thread_client("h2_send_requests", addr, h2_send_requests(addr));
    run_multi_thread_client(
        "parking_lot_h2_send_requests",
        addr,
        parking_lot_h2_send_requests(addr),
    );

    // Multi-threaded server, single-threaded client
    let addr = "127.0.0.1:5929";
    spawn_multi_thread_server(addr);
    run_single_thread_client("h2_send_requests", addr, h2_send_requests(addr));
    run_single_thread_client(
        "parking_lot_h2_send_requests",
        addr,
        parking_lot_h2_send_requests(addr),
    );

    // Multi-threaded server, multi-threaded client
    run_multi_thread_client("h2_send_requests", addr, h2_send_requests(addr));
    run_multi_thread_client(
        "parking_lot_h2_send_requests",
        addr,
        parking_lot_h2_send_requests(addr),
    );
}
