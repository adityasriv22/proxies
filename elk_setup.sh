#Elasticserch setup
git clone https://github.com/krishnaprasad-p/ELK.git
cd ELK/ElasticSearchDocker
mkdir esdata
chmod +x esdata
cd ..
docker-compose build
docker-compose up > elastic_log.txt &

