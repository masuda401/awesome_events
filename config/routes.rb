Rails.application.routes.draw do
  resources :events, only: %i[new create show edit update destroy] do
    resources :tickets
  end

  root 'welcome#index'
  get "/auth/:provider/callback" => "sessions#create"
  delete "/logout" => "sessions#destroy"
  get 'status' => 'status#index', defaults: { format: 'json' }
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html

  resource :retirements, only: %i[new create]

  match "*path" => "application#error404", via: :all
end
