from dotenv import load_dotenv

load_dotenv()


from cleanerapi.main import app  # noqa: E402

__all__ = ["app"]
