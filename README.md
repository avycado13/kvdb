# KVDB: A Simple Key-Value Database

KVDB is a lightweight, file-based key-value database designed to mimic the functionality of Replit DB. It provides a simple RESTful API for storing, retrieving, and managing data, making it ideal for small-scale applications, prototyping, or learning about database concepts.

## Features

KVDB offers a range of features to manage your data securely and efficiently:

* **Scoped Token Authentication:** Access to data is controlled via tokens with specific permissions (`read`, `write`, `delete`, `clear`). This allows for fine-grained control over who can perform what actions.
* **Data Expiration:** Set an expiration time (in seconds) for an entire data store or individual keys. Expired data is automatically cleaned up.
* **Password Protection:** Protect individual keys with a password, requiring the password to be provided for read access.
* **One-Time Keys:** Create keys that can only be read once. After the first read, the key is automatically deleted.
* **Bulk Operations:** Use the `/bulkset` endpoint to set multiple key-value pairs in a single request.
* **Admin Panel:** A simple web-based admin panel (`/admin`) for managing the database, including listing all data stores and clearing all data.
* **Swagger UI:** Interactive API documentation and testing interface available at `/swagger`.
* **Web Dashboard:** A user-friendly web interface (`/dashboard`) for creating and managing data stores.

## API Endpoints

The following is a summary of the available API endpoints:

### Core Operations

* `POST /create`: Create a new data store. Returns an `id` and a `token` for access.
* `GET /{id}`: Retrieve all key-value pairs from a data store.
* `POST /set/{id}`: Set a value for a specific key.
* `PUT /{id}/{key}`: Update the value of an existing key.
* `GET /get/{id}/{key}`: Retrieve the value of a specific key.
* `DELETE /delete/{id}/{key}`: Delete a specific key.
* `POST /delete/{id}`: Delete an entire data store.
* `GET /list/{id}`: List all keys in a data store.
* `POST /bulkset/{id}`: Set multiple key-value pairs at once.

### Admin Operations

* `GET /admin/list-all`: List all data store IDs (requires admin key).
* `POST /admin/nuke`: Delete all data stores (requires admin key).
* `POST /clear_expired`: Manually clear all expired data (requires admin key).

### UI and Documentation

* `GET /`: Main index page.
* `GET /endpoints`: List all available API endpoints.
* `GET /swagger`: Interactive Swagger UI for API testing.
* `GET /dashboard`: Web dashboard for managing data stores.
* `GET /health`: Health check endpoint.

## Getting Started

### Prerequisites

* Python 3.10+
* `uv`

### Installation and Setup

1. Clone the repository:

    ```bash
    git clone https://github.com/avycado13/kvdb.git
    cd kvdb
    ```

2. Install the dependencies:

    ```bash
    uv sync
    ```

3. Set environment variables (optional):
    * `SECRET_KEY`: A secret key for hashing passwords. If not set, a random key will be generated.
    * `ADMIN_KEY`: The key for accessing admin endpoints. If not set, the default is `default_admin`.
    * `DATA_DIR`: The directory to store data files. Defaults to `data/`.

### Running the Application

To start the development server, run:

```bash
./run.sh
```

The application will be available at `http://localhost:5000`.

## Project Structure

* `app/`: Main application code.
  * `__init__.py`: Flask application factory.
  * `routes.py`: API and web interface routes.
  * `helpers.py`: Utility functions.
  * `models.py`: Pydantic models for request validation.
  * `static/`: Static assets (CSS, JS).
  * `templates/`: HTML templates for the web interface.
* `data/`: Directory where data files are stored.
* `run.sh`: Script to run the application.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.
