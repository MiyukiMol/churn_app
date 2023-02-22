from app import app
import pytest
from flask import Flask
from flask_bcrypt import Bcrypt
from app import Users

bcrypt = Bcrypt (app)

@pytest.fixture
def test_client ():
    users = Users()
    users.insert('test100','test100','test100@test.fr',bcrypt.generate_password_hash('123456').decode('utf-8'))
    return users

def test_add_user ():
    user = Users(username="user_name", name="name", email="mail@test.fr", password_hash=bcrypt.generate_password_hash('123456').decode ('utf-8'))
    assert user.username == 'user_name'
    assert user.name == 'name'
    assert user.email == 'mail@test.fr'
    assert user.password_hash != '123456'

def test_login_page():
    user = Users(username="user_name", password_hash=bcrypt.generate_password_hash('123456').decode ('utf-8'))
    response = app.test_client(user).get('/login')
    assert response.status_code == 200

def test_home_route():
    response = app.test_client().get('/test')
    assert response.status_code == 200
    assert b"root" in response.data

