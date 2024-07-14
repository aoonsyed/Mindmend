import django
import os

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'emdr.settings')
django.setup()

from django.db import connection

def clean_emails():
    with connection.cursor() as cursor:
        # Ensure emails are lowercase
        cursor.execute("""
        UPDATE mindmend_customuser
        SET email = LOWER(email)
        """)

        # Identify duplicate emails
        cursor.execute("""
        SELECT email, COUNT(*)
        FROM mindmend_customuser
        GROUP BY email
        HAVING COUNT(*) > 1
        """)
        duplicates = cursor.fetchall()

        for email, count in duplicates:
            # Get all IDs for duplicate emails except the first one
            cursor.execute("""
            SELECT id
            FROM mindmend_customuser
            WHERE email = %s
            ORDER BY id
            """, [email])
            ids = [row[0] for row in cursor.fetchall()]

            # Keep the first ID and delete the rest
            for id_to_delete in ids[1:]:
                cursor.execute("""
                DELETE FROM mindmend_customuser
                WHERE id = %s
                """, [id_to_delete])

    print("Successfully cleaned emails")

if __name__ == "__main__":
    clean_emails()
