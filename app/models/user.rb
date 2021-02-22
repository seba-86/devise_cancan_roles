class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  belongs_to :role, optional: true
  has_many :items, dependent: :destroy
  validates :name, presence: :true
  validates_uniqueness_of :email
  before_save :assing_role

  def assing_role
    self.role = Role.find_by name: 'Regular' if role.nil?
  end
end
