# Educational Management System (EMS)

A comprehensive web-based platform for managing educational content, tracking progress, and conducting assessments.

## Features

- **User Management**
  - Role-based access control (Admin, Supervisor, Employee)
  - User registration and authentication
  - Team management and organization

- **Content Management**
  - Upload and organize educational materials
  - Support for various file types (PDF, DOC, DOCX, PPT, PPTX, TXT, MP4, ZIP)
  - Category-based content organization
  - Required content tracking

- **Progress Tracking**
  - Individual progress dashboard
  - Team progress monitoring for supervisors
  - Time spent tracking
  - Recent activity timeline
  - Progress reports and analytics

- **Quiz System**
  - Create and manage quizzes
  - Multiple question types (Multiple Choice, True/False, Text)
  - Automatic grading
  - Quiz results and performance tracking
  - Pass/Fail criteria management

## Installation

1. Clone or download the repository
2. Set up a Python virtual environment (Optional but recommended):
   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source venv/bin/activate
     ```

4. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

5. Run the application:
   ```bash
   python run.py
   ```

## Project Structure

```
ElearningFTP/
├── run.py              # Main application file
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── static/            # Static files (CSS, JS)
│   └── css/
│       └── style.css
├── templates/         # HTML templates
│   ├── admin/        # Admin-specific templates
│   ├── supervisor/   # Supervisor-specific templates
│   └── *.html        # General templates
└── uploads/          # Uploaded content storage
```

## User Roles

1. **Administrator**
   - Manage users and teams
   - Manage categories
   - Access all content and features
   - View all progress reports

2. **Supervisor**
   - Upload content
   - Create quizzes
   - Monitor team progress
   - Manage assigned categories

3. **Employee**
   - Access learning content
   - Take quizzes
   - Track personal progress
   - View personal reports

## Dependencies

- Flask==2.3.3
- Flask-SQLAlchemy==3.0.5
- Flask-Login==0.6.2
- Flask-WTF==1.1.1
- Werkzeug==2.3.7
- email-validator==2.0.0
- python-dotenv==1.0.0

## Moving the Project

### Same Operating System
1. Copy the entire project folder (including `venv`)
2. Run `python run.py`

### Different Operating System
1. Copy the project folder (excluding `venv`)
2. Create a new virtual environment
3. Install requirements
4. Run the application

## Database

- Uses SQLite database (`ems.db`)
- Created automatically on first run
- Stores user data, content metadata, progress, and quiz information

## Security Features

- Password hashing
- Role-based access control
- Secure file uploads
- Session management
- Input validation

## Support

For any issues or questions, please contact the system administrator.
