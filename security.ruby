# Gemfile
gem 'devise'

# In terminal
rails generate devise:install
rails generate devise User
rails db:migrate

# application_controller.rb
class ApplicationController < ActionController::Base
  before_action :authenticate_user!
end

# user.rb
class User < ApplicationRecord
  devise :database_authenticatable, :registerable, :recoverable, :rememberable, :validatable
end