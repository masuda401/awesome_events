class AddIndexEventsOnOwnerId < ActiveRecord::Migration[6.0]
  def change
    add_index :events, :owner_id
  end
end
