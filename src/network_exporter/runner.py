import logging

import typer
import uvicorn

cli = typer.Typer()


@cli.command()
def run(devMode: bool = False, port: int = 8080):
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(format=log_format, level=logging.INFO)

    log_config = uvicorn.config.LOGGING_CONFIG
    log_config["formatters"]["access"]["fmt"] = "%(asctime)s - %(levelname)s - %(message)s"
    log_config["formatters"]["default"]["fmt"] = "%(asctime)s - %(levelname)s - %(message)s"

    logger = logging.getLogger(__name__)

    if devMode:
        logger.info("Running in devMode with autoreload.")
        uvicorn.run(
            "network_exporter.app:app",
            host="0.0.0.0",
            port=port,
            reload=True,
            workers=1,
            log_config=log_config,
        )
    else:
        uvicorn.run(
            "network_exporter.app:app",
            host="0.0.0.0",
            port=port,
            log_level="info",
            workers=5,
            limit_max_requests=20000,
        )


def main():
    cli()


if __name__ == "__main__":
    main()
