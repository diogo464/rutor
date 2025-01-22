use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;
use color_eyre::Result;
use ratatui::{
    crossterm::event,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize as _},
    symbols,
    text::Line,
    widgets::{Block, Borders, LineGauge, Padding, Row, Table},
    DefaultTerminal, Frame,
};
use rutor::{TorrentInfo, TorrentView, TorrentViewState};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerWidget};

pub struct ByteDisplay(u64);

impl std::fmt::Display for ByteDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (n, suffix) = if self.0 > 1024 * 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0 * 1024.0), "GiB")
        } else if self.0 > 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0), "MiB")
        } else if self.0 > 1024 {
            (self.0 as f64 / 1024.0, "KiB")
        } else {
            (self.0 as f64, "B")
        };
        write!(f, "{n} {suffix}")
    }
}

pub struct ByteRateDisplay(u64);

impl std::fmt::Display for ByteRateDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (n, suffix) = if self.0 > 1024 * 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0 * 1024.0), "GiB/s")
        } else if self.0 > 1024 * 1024 {
            (self.0 as f64 / (1024.0 * 1024.0), "MiB/s")
        } else if self.0 > 1024 {
            (self.0 as f64 / 1024.0, "KiB/s")
        } else {
            (self.0 as f64, "B/s")
        };
        write!(f, "{n} {suffix}")
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Debug, Parser)]
enum SubCommand {
    View(ViewArgs),
    Download(DownloadArgs),
}

#[derive(Debug, Parser)]
struct ViewArgs {
    #[clap(default_value = "bunny.torrent")]
    torrent: String,
}

#[derive(Debug, Parser)]
struct DownloadArgs {
    #[clap(default_value = "bunny.torrent")]
    torrent: String,

    #[clap(long)]
    peers: Vec<SocketAddr>,

    #[clap(long)]
    listen: Option<SocketAddr>,

    #[clap(long)]
    no_trackers: bool,

    #[clap(long)]
    seed: bool,

    #[clap(long)]
    assume_complete: bool,
}

struct RenderSharedState {
    view: TorrentView,
    exit: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    color_eyre::install().unwrap();
    //let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    tui_logger::init_logger(tui_logger::LevelFilter::Trace).unwrap();
    tracing_subscriber::registry()
        //.with(fmt_layer)
        .with(tui_logger::tracing_subscriber_layer())
        .with(filter_layer)
        .init();

    match args.subcmd {
        SubCommand::View(args) => view(args).await,
        SubCommand::Download(args) => download(args).await,
    }
}

async fn view(args: ViewArgs) -> Result<()> {
    let content = tokio::fs::read(&args.torrent).await?;
    let torrent_info = TorrentInfo::decode(&content)?;
    println!("{:#?}", torrent_info);
    Ok(())
}

async fn download(args: DownloadArgs) -> Result<()> {
    let terminal = ratatui::init();
    let result = download_run(args, terminal).await;
    ratatui::restore();
    result
}

async fn download_run(mut args: DownloadArgs, terminal: DefaultTerminal) -> Result<()> {
    let content = std::fs::read(&args.torrent).unwrap();
    let torrent_info = TorrentInfo::decode(&content)?;
    let session_config = rutor::SessionConfig {
        listen_addr: args.listen,
    };
    let session = rutor::Session::new_with(session_config);
    let torrent_config = rutor::TorrentConfig {
        use_trackers: !args.no_trackers,
        assume_complete: args.assume_complete,
        ..Default::default()
    };
    let torrent = session.torrent_add_with(torrent_info, torrent_config).await;
    let render_state = Arc::new(Mutex::new(RenderSharedState {
        view: torrent.view().await,
        exit: false,
    }));
    let render_handle = tokio::task::spawn_blocking({
        let state = render_state.clone();
        move || render_loop(terminal, state)
    });

    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let view = torrent.view().await;
        if view.state == TorrentViewState::Running && !args.peers.is_empty() {
            for peer in &args.peers {
                torrent.connect(*peer);
            }
            args.peers.clear();
        }
        render_state.lock().unwrap().view = view;
        if torrent.completed().await && !args.seed || render_handle.is_finished() {
            break;
        }
    }
    Ok(())
}

fn render_loop(mut terminal: DefaultTerminal, state: Arc<Mutex<RenderSharedState>>) -> Result<()> {
    loop {
        let view = {
            let state = state.lock().unwrap();
            if state.exit {
                break;
            }
            state.view.clone()
        };
        terminal.draw(move |frame| render(frame, &view))?;
        if event::poll(Duration::from_millis(500))? {
            if matches!(event::read()?, event::Event::Key(_)) {
                break;
            }
        }
    }
    Ok(())
}

fn render_text_box(frame: &mut Frame, rect: Rect, title: &str, content: impl std::fmt::Display) {
    let block = Block::new().title(title).borders(Borders::all());
    let area = block.inner(rect);
    let text = Line::from(content.to_string());
    frame.render_widget(block, rect);
    frame.render_widget(text, area);
}

fn render_peers_table(frame: &mut Frame, rect: Rect, view: &TorrentView) {
    // Columns widths are constrained in the same way as Layout...
    let widths = [
        Constraint::Length(48),
        Constraint::Length(24),
        Constraint::Length(16),
        Constraint::Length(16),
    ];

    let mut rows = Vec::with_capacity(view.peers.len());
    let mut peers = view.peers.clone();
    peers.sort_by_key(|p| std::cmp::Reverse(p.upload_rate.max(p.download_rate)));

    for peer in peers {
        rows.push(Row::new(vec![
            format!("{:?}", peer.id),
            peer.addr.to_string(),
            ByteRateDisplay(u64::from(peer.upload_rate)).to_string(),
            ByteRateDisplay(u64::from(peer.download_rate)).to_string(),
        ]));
    }

    let table = Table::new(rows, widths)
        // ...and they can be separated by a fixed spacing.
        .column_spacing(1)
        // It has an optional header, which is simply a Row always visible at the top.
        .header(
            Row::new(vec!["ID", "Address", "Upload", "Download"])
                .style(Style::new().bold())
                // To add space between the header and the rest of the rows, specify the margin
                .bottom_margin(1),
        )
        // As any other widget, a Table can be wrapped in a Block.
        .block(Block::new().title("Peers"));

    let block = Block::new().title("Peers").borders(Borders::all());
    frame.render_widget(table.block(block), rect);
}

fn render_progress_bar(frame: &mut Frame, rect: Rect, view: &TorrentView) {
    let gauge = LineGauge::default()
        .block(Block::bordered().title("Progress"))
        .filled_style(Style::new().white().on_black().bold())
        .line_set(symbols::line::THICK)
        .ratio(view.progress);
    frame.render_widget(gauge, rect);
}

fn render_logs(frame: &mut Frame, rect: Rect) {
    let logger = TuiLoggerWidget::default()
        .block(Block::bordered().title("Logs"))
        .style_error(Style::default().fg(Color::Red))
        .style_debug(Style::default().fg(Color::Green))
        .style_warn(Style::default().fg(Color::Yellow))
        .style_trace(Style::default().fg(Color::Magenta))
        .style_info(Style::default().fg(Color::Cyan))
        .output_separator(':')
        .output_timestamp(Some("%H:%M:%S".to_string()))
        .output_level(Some(TuiLoggerLevelOutput::Abbreviated))
        .output_target(true)
        .output_file(true)
        .output_line(true)
        .style(Style::default().fg(Color::White));
    frame.render_widget(logger, rect);
}

fn render(frame: &mut Frame, view: &TorrentView) {
    let block = Block::new()
        .borders(Borders::all())
        .title("rutor")
        .padding(Padding::uniform(1));
    let area = block.inner(frame.area());

    let [top, bottom] =
        Layout::vertical([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).areas(area);
    let [top_left, top_right] =
        Layout::horizontal([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).areas(top);

    let [tl_name, tl_size, tl_num_files, _, tl_status, tl_progress] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(3),
    ])
    .areas(top_left);

    frame.render_widget(&block, frame.area());
    render_text_box(frame, tl_name, "Name", view.info.name());
    render_text_box(frame, tl_size, "Size", view.info.total_size());
    render_text_box(
        frame,
        tl_num_files,
        "Number of Files",
        view.info.files().len(),
    );
    render_text_box(
        frame,
        tl_status,
        "Status",
        match view.state {
            TorrentViewState::Paused => "paused",
            TorrentViewState::Running => "running",
            TorrentViewState::Checking => "checking",
        },
    );
    render_progress_bar(frame, tl_progress, &view);
    render_peers_table(frame, top_right, &view);
    render_logs(frame, bottom);
}
