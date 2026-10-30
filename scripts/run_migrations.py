"""Run database migrations programmatically via Alembic."""

import os

from alembic import command
from alembic.config import Config


def run_migrations() -> None:
    config_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "apps", "api", "alembic.ini")
    )
    print(f"Applying database migrations using config: {config_path}")
    alembic_cfg = Config(config_path)
    command.upgrade(alembic_cfg, "head")
    print("Database migrations applied successfully.")


if __name__ == "__main__":
    run_migrations()
