use clamav_async::{
    callback::{EngineCallback, ScanLogicResult},
    engine::{Engine, ScanEvent},
    fmap::Fmap,
    initialize,
    scan_settings::{GeneralFlags, ParseFlags, ScanSettings},
};
use std::{env, fs::File, path::PathBuf};
use tokio_stream::StreamExt;

fn scan_settings() -> ScanSettings {
    let mut settings = ScanSettings::default();
    settings.set_parse(&ParseFlags::all());
    settings.set_general(&GeneralFlags::CL_SCAN_GENERAL_HEURISTICS);
    settings
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| "callback_decisions".into())
        .to_string_lossy()
        .into_owned();
    let db_path = match args.next() {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("usage: {program} <database-dir> <file-to-scan>");
            std::process::exit(2);
        }
    };
    let file_path = match args.next() {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("usage: {program} <database-dir> <file-to-scan>");
            std::process::exit(2);
        }
    };

    initialize()?;

    let mut engine = Engine::new();
    engine.register_callback(
        EngineCallback::FileType,
        Box::new(|layer| {
            let file_type = layer.type_().expect("file type should be available");
            let file_size = layer.file_size();

            if file_type == "CL_TYPE_HTML" {
                ScanLogicResult::Match
            } else if file_size < 20 {
                ScanLogicResult::Abort
            } else {
                ScanLogicResult::Success
            }
        }),
    );

    engine.load_databases(&db_path).await?;
    engine.compile().await?;

    let target = Fmap::try_from(File::open(&file_path)?)?;
    let filename = file_path.file_name().map(|name| name.to_string_lossy());
    let mut events = engine.scan(
        target,
        filename.as_deref(),
        None,
        None,
        None,
        scan_settings(),
    )?;

    while let Some(event) = events.next().await {
        match event {
            ScanEvent::Result(result) => println!("result: {result:?}"),
            other => println!("event: {other:?}"),
        }
    }

    Ok(())
}
