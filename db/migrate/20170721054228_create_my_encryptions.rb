class CreateMyEncryptions < ActiveRecord::Migration
  def change
    create_table :my_encryptions do |t|

      t.timestamps null: false
    end
  end
end
