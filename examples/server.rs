extern crate env_logger;
extern crate futures;
extern crate thrussh;
extern crate thrussh_keys;
extern crate tokio;
use anyhow::Context;
use bytes::{BufMut, BytesMut};
use futures::SinkExt;
use futures::{FutureExt, StreamExt};
use futures_util::stream::{SplitSink, SplitStream};
use log::{debug, error};
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use thrussh::{
    client::{
        self,
        channel::{ChannelExt, ChannelReader, ChannelWriter},
        shell::upgrade_to_shell,
        Channel, Handle, Msg,
    },
    Disconnect,
};
use thrussh_keys::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, Sender, UnboundedReceiver, UnboundedSender};
use tokio_tungstenite::{accept_async, WebSocketStream};
use tungstenite::Message;

struct Client {}

impl client::Handler for Client {
    type FutureUnit = futures::future::Ready<Result<(Self, client::Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, bool), anyhow::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        futures::future::ready(Ok((self, b)))
    }
    fn finished(self, session: client::Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, session)))
    }
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        println!("check_server_key: {:?}", server_public_key);
        self.finished_bool(true)
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let config = thrussh::client::Config::default();
    let config = Arc::new(config);
    let sh = Client {};

    //let key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
    //let mut agent = thrussh_keys::agent::client::AgentClient::connect_env().await.unwrap();
    //agent.add_identity(&key, &[]).await.unwrap();
    let kp = thrussh_keys::load_secret_key("id_rsa", None).unwrap();
    let mut handle = thrussh::client::connect(config, "127.0.0.1:2222", sh)
        .await
        .unwrap();
    let kp_ref = Arc::new(kp);
    let auth_res = handle
        .authenticate_publickey("jason", kp_ref)
        .await
        .unwrap();
    assert!(auth_res, true);

    ws_server(handle)
        .await
        .map_err(|e| debug!("ws server exit with error: {:?}", e));
}

async fn tick(sender: Sender<Msg>, mut recv: UnboundedReceiver<()>) -> Result<(), anyhow::Error> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        debug!("ticking");
        tokio::select! {
            _ = recv.recv() => {
                debug!("tick stop");
                return Ok(())
            }
            _ = interval.tick() => {
                debug!("=== sending keepalive msg");
                sender.send(Msg::KeepAlive).await.map_err(|e| debug!("failed to send keepalive: {:?}", e));
            }
        }
    }
}

async fn handle_websocket_incoming(
    mut incoming: SplitStream<WebSocketStream<TcpStream>>,
    mut sshshell_writer: ChannelWriter,
    websocket_sender: UnboundedSender<Message>,
) -> Result<(), anyhow::Error> {
    let (stop_sender, stop_receiver) = unbounded_channel();
    let msg_sender = sshshell_writer.get_sender();
    tokio::spawn(tick(msg_sender, stop_receiver));
    while let Some(Ok(msg)) = incoming.next().await {
        match msg {
            Message::Binary(mut data) => match data[0] {
                0 => {
                    data.remove(0);
                    sshshell_writer.write_all(&data[..]).await?;
                }
                1 => println!("=== {}", pretty_hex::pretty_hex(&data.as_slice())),
                _ => (),
            },
            Message::Ping(data) => websocket_sender.send(Message::Pong(data))?,
            _ => (),
        };
    }
    stop_sender
        .send(())
        .map_err(|e| debug!("failed to send stop signal: {:?}", e));
    Ok(())
}

async fn handle_ssh_incoming(
    mut sshshell_reader: ChannelReader,
    websocket_sender: UnboundedSender<Message>,
) -> Result<(), anyhow::Error> {
    let mut buffer = BytesMut::with_capacity(1024);
    loop {
        buffer.clear();
        let n = sshshell_reader.read_buf(&mut buffer).await?;
        if n == 0 {
            break;
        }
        match websocket_sender.send(Message::Binary(buffer[..n].to_vec())) {
            Ok(_) => (),
            Err(e) => anyhow::bail!("failed to send msg to client: {:?}", e),
        }
    }
    Ok(())
}

async fn write_to_websocket(
    mut outgoing: SplitSink<WebSocketStream<TcpStream>, Message>,
    mut receiver: UnboundedReceiver<Message>,
) -> Result<(), anyhow::Error> {
    while let Some(msg) = receiver.recv().await {
        outgoing.send(msg).await?;
    }
    Ok(())
}

async fn handle_connection(channel: Channel, stream: TcpStream) -> Result<(), anyhow::Error> {
    let mut chan = upgrade_to_shell(channel).await?;
    let (sshshell_reader, sshshell_writer) = chan.split()?;
    let ws_stream = accept_async(stream).await?;
    let (ws_outgoing, ws_incoming) = ws_stream.split();
    let (sender, receiver) = unbounded_channel();
    let ws_sender = sender.clone();
    let res = tokio::select! {
        res = handle_websocket_incoming(ws_incoming, sshshell_writer, sender) => res,
        res = handle_ssh_incoming(sshshell_reader, ws_sender) => res,
        res = write_to_websocket(ws_outgoing, receiver) => res,
    };

    Ok(())
}

async fn ws_server(mut handle: Handle) -> Result<(), anyhow::Error> {
    let addr: SocketAddr = "127.0.0.1:8092".parse().unwrap();
    match TcpListener::bind(addr).await {
        Ok(mut listener) => {
            while let Ok((stream, peer)) = listener.accept().await {
                let mut channel = handle.channel_open_session().await?;
                let fut = async move {
                    let _ = handle_connection(channel, stream)
                        .await
                        .map_err(|e| error!("handle connection error: {:?}", e));
                };
                tokio::spawn(fut);
            }
        }
        Err(e) => return Err(anyhow::anyhow!("failed to listen: {:?}", e)),
    }
    Ok(())
}
