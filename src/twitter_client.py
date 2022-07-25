import tweepy
import pandas as pd
import json


class Twitter(object):
    @staticmethod
    def json_reader(path):
        with open(path, "r") as f:
            data = f.read()
            creds = json.loads(data)
        return creds

    @staticmethod
    def twitter_auth(consumer_key, consumer_secret, access_token, access_token_secret, bearer_token):
        auth = tweepy.OAuth1UserHandler(consumer_key, consumer_secret, access_token, access_token_secret)
        api = tweepy.API(auth)
        client = tweepy.Client(bearer_token)

        return auth, api, client

    @staticmethod
    def twitter_data_retrieve(client):
        response = client.search_recent_tweets("CVE", max_results=100)
        print(response.meta)
        for i in response:
            print(response.data)
        print(type(response))
        tweets = response.data
        # print(tweets)
        return response, tweets
        # for tweet in tweets:
        #     print(tweet.id)
        #     print(tweet.text)
        # public_tweets = api.home_timeline()
        # for tweet in public_tweets:
        #     print(tweet.text)

    # Create pandas  dataframe
    @staticmethod
    def create_tweets_dataframe():
        columns = ['Time', 'User', 'Tweet']
        data = []
        for tweet in public_tweets:
            data.append([tweet.created_at, tweet.user.screen_name, tweet.text])

        df = pd.DataFrame(data, columns=columns)

        new = df.to_csv('tweets.csv')
        print(new)

    @staticmethod
    def login():
        creds = Twitter.json_reader("credits.json")
        consumer_key = creds["project_credits"]["api_key"]
        consumer_secret = creds["project_credits"]["api_key_secret"]
        access_token = creds["project_credits"]["access_token"]
        access_token_secret = creds["project_credits"]["access_token_secret"]
        bearer_token = creds["project_credits"]["bearer_token"]

        # Authenticate with twitterAPI
        auth, api, client = Twitter.twitter_auth(consumer_key, consumer_secret, access_token, access_token_secret,
                                                 bearer_token)

        responses, tweets = Twitter.twitter_data_retrieve(client)
