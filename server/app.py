#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        bio = data.get('bio')
        image_url = data.get('image_url')

        if not username or not password:
            return {'errors': ['Username and password required']}, 422

        user = User(username=username, bio=bio, image_url=image_url)
        user.password_hash = password
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Username must be unique']}, 422

        session['user_id'] = user.id
        return user.to_dict(), 201

        user = User(username="Prabhdip")
        user.password_hash = "secret"  # <-- Add this line!

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {}, 401
        user = User.query.get(user_id)
        if not user:
            return {}, 401
        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'errors': ['Invalid username or password']}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        return {}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {}, 401
        recipes = Recipe.query.all()
        return [r.to_dict() for r in recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {}, 401
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')
        if not title or not instructions or len(instructions) < 50:
            return {'errors': ['Invalid recipe data']}, 422
        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id
        )
        try:
            db.session.add(recipe)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'errors': ['Could not create recipe']}, 422
        return recipe.to_dict(), 201

        recipe_1.user = user
        recipe_2.user = user

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)